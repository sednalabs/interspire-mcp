#!/usr/bin/env python3
"""Check private Interspire source against the MCP compatibility profile.

This script is intentionally safe for a public repository: it accepts a local
Interspire source tree, checks for reviewed route/form/API contract markers,
and emits aggregate JSON only. It must not print proprietary source snippets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ContractPattern:
    label: str
    regex: str


@dataclass(frozen=True)
class ContractCheck:
    area: str
    name: str
    relative_path: str
    patterns: tuple[ContractPattern, ...]


CHECKS: tuple[ContractCheck, ...] = (
    ContractCheck(
        area="lists",
        name="list create/read/apply routes",
        relative_path="admin/functions/lists.php",
        patterns=(
            ContractPattern("create_route", r"case\s+['\"]create['\"]"),
            ContractPattern("add_list_route", r"case\s+['\"]addlist['\"]"),
            ContractPattern("create_handler", r"function\s+CreateList\s*\("),
            ContractPattern("add_list_handler", r"function\s+AddList\s*\("),
            ContractPattern(
                "create_form_add_route",
                r"\$GLOBALS\[['\"]Action['\"]\]\s*=\s*['\"]AddList['\"]",
            ),
        ),
    ),
    ContractCheck(
        area="lists",
        name="list metadata fields",
        relative_path="admin/functions/lists.php",
        patterns=(
            ContractPattern("list_name_field", r"['\"]Name['\"]"),
            ContractPattern("owner_name_field", r"['\"]OwnerName['\"]"),
            ContractPattern("owner_email_field", r"['\"]OwnerEmail['\"]"),
            ContractPattern("reply_to_field", r"['\"]ReplyToEmail['\"]"),
            ContractPattern("bounce_email_field", r"requestGetPOST\(['\"]BounceEmail['\"]"),
            ContractPattern("unsubscribe_mailto_field", r"requestGetPOST\(['\"]UnsubscribeMailto['\"]"),
            ContractPattern("owner_notify_field", r"requestGetPOST\(['\"]NotifyOwner['\"]"),
            ContractPattern("visible_fields_multiselect", r"requestGetPOST\(['\"]VisibleFields['\"]"),
            ContractPattern("available_fields_multiselect", r"requestGetPOST\(['\"]AvailableFields['\"]"),
            ContractPattern("webhook_count_hidden_field", r"requestGetPOST\(['\"]total_webhooks['\"]"),
            ContractPattern("webhook_url_fields", r"requestGetPOST\(['\"]WebhookUrl_"),
            ContractPattern("webhook_event_fields", r"requestGetPOST\(['\"]webhook_event_"),
            ContractPattern("bounce_process_field", r"requestGetPOST\(['\"]bounce_process['\"]"),
        ),
    ),
    ContractCheck(
        area="lists",
        name="list form template",
        relative_path="admin/com/templates/lists_form.tpl",
        patterns=(
            ContractPattern("list_editor_form", r"name=['\"]frmListEditor['\"]"),
            ContractPattern(
                "list_form_action_placeholder",
                r"action=['\"]index\.php\?Page=Lists&Action=%%GLOBAL_Action%%['\"]",
            ),
            ContractPattern("list_name_input", r"name=['\"]Name['\"]"),
            ContractPattern("owner_name_input", r"name=['\"]OwnerName['\"]"),
            ContractPattern("owner_email_input", r"name=['\"]OwnerEmail['\"]"),
            ContractPattern("reply_to_input", r"name=['\"]ReplyToEmail['\"]"),
            ContractPattern("bounce_email_input", r"name=['\"]BounceEmail['\"]"),
            ContractPattern("visible_fields_input", r"name=['\"]VisibleFields\[\]['\"]"),
            ContractPattern("available_fields_input", r"name=['\"]AvailableFields\[\]['\"]"),
            ContractPattern("webhook_region", r"%%GLOBAL_webhook_data%%"),
        ),
    ),
    ContractCheck(
        area="campaigns",
        name="campaign management routes",
        relative_path="admin/functions/newsletters.php",
        patterns=(
            ContractPattern("copy_route", r"case\s+['\"]copy['\"]"),
            ContractPattern("edit_route", r"case\s+['\"]edit['\"]"),
            ContractPattern("create_route", r"case\s+['\"]create['\"]"),
            ContractPattern("edit_handler", r"function\s+EditNewsletter\s*\("),
            ContractPattern("create_handler", r"function\s+CreateNewsletter\s*\("),
        ),
    ),
    ContractCheck(
        area="send",
        name="send wizard boundaries",
        relative_path="admin/functions/send.php",
        patterns=(
            ContractPattern("send_process_handler", r"function\s+Process\s*\("),
            ContractPattern("send_step_2", r"Step2"),
            ContractPattern("send_step_3", r"Step3"),
            ContractPattern("send_step_4", r"Step4"),
            ContractPattern("schedule_boundary", r"Schedule"),
        ),
    ),
    ContractCheck(
        area="xml",
        name="xml front controller",
        relative_path="admin/com/xml.php",
        patterns=(
            ContractPattern("request_type_parameter", r"requesttype"),
            ContractPattern("request_method_parameter", r"requestmethod"),
            ContractPattern("username_parameter", r"username"),
            ContractPattern("token_parameter", r"usertoken"),
            ContractPattern("xml_body_input", r"php://input"),
        ),
    ),
    ContractCheck(
        area="xml",
        name="xml policy allowlist",
        relative_path="admin/com/xml_allowlist.php",
        patterns=(
            ContractPattern("authentication_allowlist", r"authentication"),
            ContractPattern("lists_allowlist", r"lists"),
            ContractPattern("subscribers_allowlist", r"subscribers"),
            ContractPattern("newsletters_allowlist", r"newsletters"),
            ContractPattern("lists_create_allowlist", r"['\"]Create['\"]"),
            ContractPattern("lists_copy_allowlist", r"['\"]CopyList['\"]"),
        ),
    ),
    ContractCheck(
        area="xml",
        name="xml list api write candidates",
        relative_path="admin/functions/api/lists.php",
        patterns=(
            ContractPattern("create_method", r"function\s+Create\s*\("),
            ContractPattern("save_method", r"function\s+Save\s*\("),
            ContractPattern("copy_method", r"function\s+Copy\s*\("),
            ContractPattern("get_lists_method", r"function\s+GetLists\s*\("),
        ),
    ),
    ContractCheck(
        area="xml",
        name="xml newsletter api write candidates",
        relative_path="admin/functions/api/newsletters.php",
        patterns=(
            ContractPattern("create_method", r"function\s+Create\s*\("),
            ContractPattern("save_method", r"function\s+Save\s*\("),
            ContractPattern("copy_method", r"function\s+Copy\s*\("),
            ContractPattern("get_newsletters_method", r"function\s+GetNewsletters\s*\("),
        ),
    ),
)


def read_text(root: Path, relative_path: str) -> str | None:
    path = root / relative_path
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return None


def check_patterns(
    text: str | None,
    patterns: Iterable[ContractPattern],
) -> tuple[bool, list[str]]:
    if text is None:
        return False, ["file_present"]
    missing = [
        pattern.label
        for pattern in patterns
        if re.search(pattern.regex, text, re.IGNORECASE) is None
    ]
    return not missing, missing


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a private Interspire source tree against public MCP compatibility contracts."
    )
    parser.add_argument(
        "--source-root",
        default=os.environ.get("INTERSPIRE_SOURCE_ROOT"),
        help="Path to private Interspire source root. Defaults to INTERSPIRE_SOURCE_ROOT.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON.",
    )
    args = parser.parse_args()
    if not args.source_root:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "source_root_required",
                    "message": "Pass --source-root or set INTERSPIRE_SOURCE_ROOT.",
                }
            ),
            file=sys.stderr,
        )
        return 2

    root = Path(args.source_root).expanduser().resolve()
    results = []
    for check in CHECKS:
        text = read_text(root, check.relative_path)
        ok, missing = check_patterns(text, check.patterns)
        results.append(
            {
                "area": check.area,
                "name": check.name,
                "relative_path": check.relative_path,
                "ok": ok,
                "pattern_count": len(check.patterns),
                "missing_count": len(missing),
                "missing_contracts": missing,
            }
        )

    failed = [result for result in results if not result["ok"]]
    payload = {
        "ok": not failed,
        "source_root_checked": True,
        "checks": len(results),
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "results": results,
        "output_policy": (
            "aggregate contract status only; no source root, proprietary snippets, "
            "or raw checker patterns emitted"
        ),
    }
    print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
