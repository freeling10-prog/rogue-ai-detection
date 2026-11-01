"""Sample guard policy from the $149 Quick Check sample report (synthetic helpdesk server).

Python 3.12, standard library only, deterministic: the same calls in the same
order always give the same decisions. Log-only by default; the client decides
whether to switch any rule to enforce. It is a recommendation, not a fix that
was applied to anyone's system.

Rules:
  G1  Once a session has read untrusted content (ticket text, a fetched
      attachment), send_reply may only go to the ticket's own requester.
  G2  get_integration_token is never callable by the agent.
  G3  post_slack_message after untrusted content may only use an allow-listed
      channel and must not carry a token-shaped string.
  G4  fetch_attachment only from the client's own file host.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

UNTRUSTED_SOURCES = frozenset({"search_tickets", "get_ticket", "fetch_attachment"})
NEVER_CALLABLE = frozenset({"get_integration_token"})
SLACK_CHANNELS = frozenset({"#support-escalations"})
ATTACHMENT_HOST = re.compile(r"^https://files\.client-a\.example/[A-Za-z0-9/_.-]{1,200}$")
TOKEN_SHAPE = re.compile(r"(?:sk|xox[abpr]|ghp|glpat)[-_][A-Za-z0-9_-]{12,}|[A-Za-z0-9+/]{40,}={0,2}")


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule: str
    reason: str


@dataclass
class Session:
    requester_email: str
    mode: str = "log"  # "log" records would-deny decisions and allows; "enforce" denies
    tainted: bool = False
    log: list[str] = field(default_factory=list)

    def check(self, tool: str, args: dict) -> Decision:
        d = self._decide(tool, args)
        self.log.append(json.dumps({"tool": tool, "rule": d.rule, "allow": d.allow, "reason": d.reason},
                                   sort_keys=True))
        if tool in UNTRUSTED_SOURCES and d.allow:
            self.tainted = True
        if not d.allow and self.mode != "enforce":
            return Decision(True, d.rule, "log-only: would deny: " + d.reason)
        return d

    def _decide(self, tool: str, args: dict) -> Decision:
        if tool in NEVER_CALLABLE:
            return Decision(False, "G2", "token tools are server-side only")
        if tool == "fetch_attachment" and not ATTACHMENT_HOST.match(str(args.get("url", ""))):
            return Decision(False, "G4", "attachment URL is not on the client file host")
        if self.tainted and tool == "send_reply":
            to = str(args.get("to") or self.requester_email).strip().lower()
            if to != self.requester_email.strip().lower():
                return Decision(False, "G1", "reply after untrusted input must go to the requester")
        if self.tainted and tool == "post_slack_message":
            if args.get("channel") not in SLACK_CHANNELS:
                return Decision(False, "G3", "channel not allow-listed after untrusted input")
            if TOKEN_SHAPE.search(str(args.get("text", ""))):
                return Decision(False, "G3", "token-shaped string in message")
        return Decision(True, "-", "allowed")


if __name__ == "__main__":
    s = Session(requester_email="requester@example.com", mode="enforce")
    for call in (("get_ticket", {"ticket_id": "T-104233"}),
                 ("send_reply", {"ticket_id": "T-104233", "to": "attacker@example.net", "body": "..."}),
                 ("send_reply", {"ticket_id": "T-104233", "body": "Thanks, fixed."})):
        print(call[0], s.check(*call))
