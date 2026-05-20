import argparse
import json
import logging
import os

import requests

logger = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self, bot_token: str, channel_id: str, internal_channel: bool = True):
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.internal_channel = internal_channel
        self.headers = {
            "Authorization": f"Bearer {bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        }

    def notify(self, summary: dict, report_url: str = "") -> None:
        blocks = self._build_summary_blocks(summary, report_url=report_url)
        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=self.headers,
            json={
                "channel": self.channel_id,
                "text": "Snyk Auto-Fix Report",
                "blocks": blocks,
            },
            timeout=15,
        )
        resp_data = resp.json()
        thread_ts = resp_data.get("ts", "")

        report_path = summary.get("report_path", "")
        if report_path and os.path.exists(report_path) and thread_ts:
            self._upload_report(report_path, thread_ts)

    def _upload_report(self, report_path: str, thread_ts: str) -> None:
        with open(report_path, "rb") as f:
            requests.post(
                "https://slack.com/api/files.upload",
                headers={"Authorization": f"Bearer {self.bot_token}"},
                data={
                    "channels": self.channel_id,
                    "thread_ts": thread_ts,
                    "title": "Snyk Auto-Fix Detailed Report",
                    "filename": "fix_report.md",
                    "filetype": "markdown",
                },
                files={"file": f},
                timeout=30,
            )

    def notify_code_analysis(
        self, result: dict, trigger_user: str = "", report_url: str = ""
    ) -> None:
        """Send Slack notification for scan-code triage results (plain text)."""
        repo = result.get("repo", "unknown")
        total = result.get("total_findings", 0)
        unique = result.get("unique_issue_count", total)
        fp = len(result.get("false_positives", []))
        tp = len(result.get("true_positives", []))
        nr = len(result.get("needs_review", []))
        ignored = result.get("ignored_count", 0)

        lines = [
            f":mag: *Snyk Code Analysis Triage* — `{repo}`",
            f"*{unique}* issues analyzed",
            "",
            f":white_check_mark: *{fp}* false positives"
            + (f" (*{ignored}* auto-ignored in Snyk)" if ignored else ""),
            f":rotating_light: *{tp}* true positives (action needed)",
            f":eyes: *{nr}* needs human review",
        ]

        # Show top true positives inline
        for item in result.get("true_positives", [])[:3]:
            title = item.get("title", "")
            sev = item.get("severity", "?").upper()
            lines.append(f"  :red_circle: [{sev}] {title}")

        if trigger_user:
            lines.append(f"\nTriggered by {trigger_user}")
        if report_url:
            lines.append(f":page_facing_up: <{report_url}|View full scan report>")
        else:
            lines.append("_See pipeline artifacts for full HTML report._")

        text = "\n".join(lines)
        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=self.headers,
            json={"channel": self.channel_id, "text": text},
            timeout=15,
        )
        resp_data = resp.json()
        if not resp_data.get("ok"):
            logger.error(f"Slack API error: {resp_data.get('error', 'unknown')}")

    def _build_summary_blocks(self, summary: dict, report_url: str = "") -> list[dict]:
        results = summary.get("results", [])
        queued = summary.get("queued", [])
        clean_count = summary.get("clean_count", 0)
        trigger = summary.get("trigger_source", "cron")
        user = summary.get("trigger_user", "")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Snyk Auto-Fix Report"},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Trigger: *{trigger}*"
                        + (f" by {user}" if user else "")
                        + f" | Repos processed: *{len(results)}*",
                    }
                ],
            },
            {"type": "divider"},
        ]

        for result in results:
            repo = result.get("repo", "")
            success = result.get("success", False)
            pr_url = result.get("pr_url", "")
            fixes = result.get("fixes_applied", [])
            error = result.get("error", "")

            status = "passed" if success else "failed"
            emoji = "white_check_mark" if success else "x"

            fix_lines = []
            for fix in fixes:
                line = f"`{fix['package']}` {fix.get('from', '')} -> {fix['to']}"
                if self.internal_channel and fix.get("severity"):
                    line += f" ({fix['severity'].capitalize()})"
                fix_lines.append(line)

            text = f":{emoji}: *{repo}*\n"
            if fixes:
                text += "\n".join(fix_lines) + "\n"
            if pr_url:
                text += f"PR: {pr_url}\n"
            if error:
                text += f"Error: {error}\n"

            # Show unfixable/transitive issues when no fixes were applied
            unfixable = result.get("unfixable", [])
            issues_before = result.get("issues_before", 0)
            if not fixes and not error and unfixable:
                text += f"_{issues_before} issue(s) found — all transitive (waiting for upstream fix):_\n"
                for u in unfixable[:5]:
                    text += f"  - `{u.get('package', '?')}`: {u.get('reason', 'transitive')}\n"
                if len(unfixable) > 5:
                    text += f"  _...and {len(unfixable) - 5} more_\n"
            elif not fixes and not error and issues_before == 0:
                text += "_No open vulnerabilities found._\n"

            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

        if queued:
            queued_text = "*Queued for next run:*\n"
            for q in queued[:5]:
                queued_text += f"- {q.get('name', q.get('repo', '?'))} ({q['issue_count']} issues, {q['top_severity']}, {q['sla_days_remaining']}d SLA)\n"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": queued_text}})

        if clean_count > 0:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Clean repos: {clean_count} with no open issues"}],
            })

        if report_url:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f":page_facing_up: <{report_url}|View full report>"}],
            })

        return blocks


def main():
    parser = argparse.ArgumentParser(description="Snyk Auto-Fix Slack Notifier")
    parser.add_argument("--results-dir", required=True, help="Directory with result artifacts")
    parser.add_argument("--trigger-source", default="cron")
    parser.add_argument("--trigger-user", default="")
    args = parser.parse_args()

    summary_path = os.path.join(args.results_dir, "summary.json")
    with open(summary_path) as f:
        summary = json.load(f)
    summary["trigger_source"] = args.trigger_source
    summary["trigger_user"] = args.trigger_user

    notifier = SlackNotifier(
        bot_token=os.environ.get("SLACK_BOT_TOKEN", ""),
        channel_id=os.environ.get("SLACK_CHANNEL_ID", ""),
        internal_channel=True,
    )
    notifier.notify(summary)


if __name__ == "__main__":
    main()
