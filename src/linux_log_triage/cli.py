"""CLI and local JSON/CSV/Markdown serialization."""

import argparse
import copy
import csv
import io
import json
from pathlib import Path
import sys

from .core import analyze, parse_offset


def export_view(report, *, mask=False, include_raw=False):
    result = copy.deepcopy(report)
    users, addresses = {}, {}

    def pseudonym(mapping, value, prefix):
        if value is None:
            return None
        if value not in mapping:
            mapping[value] = f"{prefix}-{len(mapping) + 1}"
        return mapping[value]

    for event in result["events"] + result["repetitions"]:
        if mask:
            event["user"] = pseudonym(users, event.get("user"), "user")
            event["actor"] = pseudonym(users, event.get("actor"), "user")
            event["ip"] = pseudonym(addresses, event.get("ip"), "ip")
            # Free text can contain arbitrary sensitive values, including extra users/IPs.
            event.pop("command", None)
        if mask or not include_raw:
            event.pop("raw", None)
    if mask:
        for source in result["sources"]:
            source.pop("path", None)
    result["privacy"] = dict(masked=mask, raw_included=include_raw and not mask)
    return result


def csv_safe(value):
    text = str(value) if value is not None else ""
    # Spreadsheet formula injection, including leading whitespace/control characters.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def serialize(report, fmt):
    if fmt == "json":
        return json.dumps(report, ensure_ascii=True, indent=2) + "\n"
    if fmt == "csv":
        out = io.StringIO(newline="")
        columns = ["record_type", "source", "line", "rule", "timestamp", "user", "ip", "actor",
                   "unknown_user", "action", "command", "event_rule", "count", "start", "end", "lines", "condition", "raw"]
        writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerow({"record_type": "notice", "condition": report["notice"]})
        for name in ("settings", "summary", "privacy"):
            writer.writerow({"record_type": name, "condition": json.dumps(report[name], ensure_ascii=True)})
        for source in report["sources"]:
            writer.writerow({"record_type": "source", "source": source["id"],
                             "condition": csv_safe(json.dumps(source, ensure_ascii=True))})
        for warning in report["warnings"]:
            writer.writerow({"record_type": "diagnostic", "condition": warning})
        for kind in ("events", "repetitions"):
            for event in report[kind]:
                row = dict(event, record_type=kind)
                if "lines" in row:
                    row["lines"] = ";".join(map(str, row["lines"]))
                writer.writerow({k: csv_safe(v) for k, v in row.items()})
        return out.getvalue()
    # Escape all untrusted Markdown text, including HTML and control characters.
    def safe(value):
        text = json.dumps(value, ensure_ascii=True) if isinstance(value, (list, dict)) else str(value)
        text = text.encode("unicode_escape").decode("ascii")
        for char in "\\`*_{}[]()#+-.!|<>&":
            text = text.replace(char, f"&#{ord(char)};")
        return text

    lines = ["# Linux log triage", "", report["notice"], "", "## Summary", ""]
    lines += [f"- {safe(rule)}: {count}" for rule, count in sorted(report["summary"].items())]
    lines += ["", "## Settings and privacy", "", safe(report["settings"]), "", safe(report["privacy"]),
              "", "## Sources", ""] + [f"- {safe(source)}" for source in report["sources"]]
    lines += ["", "## Diagnostics", ""] + [f"- {safe(w)}" for w in report["warnings"]]
    for kind in ("events", "repetitions"):
        lines += ["", f"## {kind.title()}", ""]
        for event in report[kind]:
            lines.append("- " + "; ".join(f"{safe(k)}: {safe(v)}" for k, v in event.items()))
    return "\n".join(lines) + "\n"


def terminal_safe(value):
    return str(value).encode("ascii", "backslashreplace").decode("ascii").replace("\x1b", "\\x1b").replace("\r", "\\r").replace("\n", "\\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Linux text-log triage; indicators require manual review.")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--year", type=int, help="year of first legacy syslog entry; Dec->Jan advances it")
    parser.add_argument("--timezone", default="UTC", help="offset for naive timestamps: UTC or +03:00 (default UTC)")
    parser.add_argument("--encoding", default="auto", help="auto: UTF-8 or BOM UTF-16; or explicit codec, e.g. cp1251")
    parser.add_argument("--max-mib", type=float, default=10, help="combined input limit, 0 < value <= 100 (default 10)")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="new local file; existing paths are never overwritten")
    parser.add_argument("--mask", action="store_true", help="pseudonymize IP/users; omit paths, commands and raw lines in export")
    parser.add_argument("--include-raw", action="store_true", help="include full evidence lines in export (disabled by --mask)")
    args = parser.parse_args(argv)
    try:
        if not 0 < args.max_mib <= 100:
            raise ValueError("max-mib must be > 0 and <= 100")
        if args.output:
            target = args.output.resolve()
            if target in {p.resolve() for p in args.files}:
                raise ValueError("output cannot be an input file")
            if args.output.exists() or args.output.is_symlink():
                raise ValueError("output already exists; choose a new path")
        report = analyze(args.files, max_bytes=int(args.max_mib * 1024 * 1024), encoding=args.encoding,
                         year=args.year, tz=parse_offset(args.timezone),
                         window_seconds=args.window_seconds, threshold=args.threshold)
        if args.output:
            content = serialize(export_view(report, mask=args.mask, include_raw=args.include_raw), args.format)
            with args.output.open("x", encoding="utf-8", newline="") as handle:
                handle.write(content)
        print(report["notice"])
        print(f"Files: {len(report['sources'])}; events: {len(report['events'])}; repeated windows: {len(report['repetitions'])}")
        print(f"Naive timestamps: {args.timezone}; legacy year: {args.year or 'unspecified (excluded from windows)'}")
        for rule, count in sorted(report["summary"].items()):
            print(f"  {rule}: {count}")
        print(f"Unknown-user events: {report['unknown_user_events']}")
        for warning in report["warnings"]:
            print(f"  {warning}")
        # References and conditions explain every rule without printing log content.
        for event in report["events"]:
            print(f"  {event['source']}:{event['line']} {event['rule']}: {event['condition']}")
        for event in report["repetitions"]:
            print(f"  {event['source']} lines {event['lines']}: {event['condition']} (count={event['count']})")
        if args.output:
            print("Export saved.")
        return 0
    except (OSError, ValueError, LookupError, OverflowError) as exc:
        print("Error: " + terminal_safe(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
