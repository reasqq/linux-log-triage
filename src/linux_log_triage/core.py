"""Bounded, read-only analysis of explicitly supplied text files."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import codecs
import ipaddress
from pathlib import Path
import re
import stat

NOTICE = "Indicators require manual review. Login failures alone do not prove compromise."
MAX_LINE = 65536
RULES = {
    "ssh_failed": "sshd message matches Failed <method> for <user> from <IP>",
    "ssh_invalid_user": "sshd message matches Invalid user <user> from <IP> or Failed ... for invalid user",
    "ssh_success": "sshd message matches Accepted <method> for <user> from <IP>",
    "sudo_command": "sudo message contains actor : ... USER=<target> ; ... COMMAND=<command>",
    "sudo_session": "sudo pam_unix session opened/closed for user <target>",
}
SSH = re.compile(r"\bsshd(?:\[\d+\])?:\s*(?P<message>.*)$")
LOGIN = re.compile(r"^(?P<status>Failed|Accepted) (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)(?:\s|$)")
INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?:\s|$)")
SUDO = re.compile(r"\bsudo(?:\[\d+\])?:\s*(?P<message>.*)$")
COMMAND = re.compile(r"^(?P<actor>\S+)\s*:\s*.*?\bUSER=(?P<user>[^;\s]+)\s*;.*?\bCOMMAND=(?P<command>.+)$")
SESSION = re.compile(r"^pam_unix\(sudo:session\): session (?P<action>opened|closed) for user (?P<user>[^\s(]+)")
ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?=\s|$)")
SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def parse_offset(value):
    if value in ("UTC", "Z"):
        return timezone.utc
    if not re.fullmatch(r"[+-]\d{2}:\d{2}", value):
        raise ValueError("timezone must be UTC or a fixed offset such as +03:00")
    hours, minutes = map(int, value[1:].split(":"))
    if hours > 23 or minutes > 59:
        raise ValueError("invalid timezone offset")
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(delta if value[0] == "+" else -delta)


def timestamp(line, year, tz):
    match = ISO.match(line)
    try:
        if match:
            dt = datetime.fromisoformat(match[1].replace("Z", "+00:00"))
            return dt.replace(tzinfo=tz) if dt.tzinfo is None else dt
        match = SYSLOG.match(line)
        if match and year is not None:
            hour, minute, second = map(int, match[3].split(":"))
            return datetime(year, MONTHS[match[1]], int(match[2]), hour, minute, second, tzinfo=tz)
    except (ValueError, KeyError, OverflowError):
        pass
    return None


def recognize(line):
    match = SSH.search(line)
    if match:
        message = match["message"]
        login = LOGIN.match(message)
        invalid = INVALID.match(message)
        if login or invalid:
            fields = (login or invalid).groupdict()
            try:
                address = str(ipaddress.ip_address(fields["ip"]))
            except ValueError:
                return None
            if login:
                kind = "ssh_success" if fields["status"] == "Accepted" else "ssh_failed"
                # One record per physical line; invalid-user status is an attribute.
                unknown = bool(fields["invalid"])
            else:
                kind, unknown = "ssh_invalid_user", True
            return dict(rule=kind, user=fields["user"], ip=address,
                        unknown_user=unknown, actor=None, command=None,
                        condition=RULES[kind] + ("; invalid user marker present" if unknown else ""))
    match = SUDO.search(line)
    if match:
        command = COMMAND.match(match["message"])
        session = SESSION.match(match["message"])
        if command or session:
            fields = (command or session).groupdict()
            kind = "sudo_command" if command else "sudo_session"
            return dict(rule=kind, user=fields["user"], ip=None, unknown_user=False,
                        actor=fields.get("actor"), command=fields.get("command"),
                        action=fields.get("action"), condition=RULES[kind])
    return None


def repetitions(events, window_seconds, threshold):
    groups = defaultdict(list)
    for event in events:
        if event["timestamp"] is not None:
            # Files are independent; do not double count overlapping exports.
            key = (event["source"], event["rule"], event["ip"], event["user"],
                   event.get("actor"), event.get("command"), event.get("action"))
            groups[key].append(event)
    results = []
    for records in groups.values():
        records.sort(key=lambda e: (e["timestamp"], e["line"]))
        # Greedy disjoint windows bound evidence size by the number of events.
        left, right = 0, 0
        while left < len(records):
            right = max(right, left)
            while right < len(records) and (records[right]["timestamp"] - records[left]["timestamp"]).total_seconds() <= window_seconds:
                right += 1
            if right - left < threshold:
                left += 1
                continue
            batch = records[left:right]
            results.append(dict(rule="repeated_event", event_rule=batch[0]["rule"],
                                source=batch[0]["source"], ip=batch[0]["ip"], user=batch[0]["user"],
                                actor=batch[0].get("actor"), count=len(batch),
                                start=batch[0]["timestamp"].isoformat(), end=batch[-1]["timestamp"].isoformat(),
                                lines=[e["line"] for e in batch],
                                condition=f"same source/rule/IP/user/actor/command/action; count >= {threshold}; span <= {window_seconds}s"))
            left = right
    return results


def analyze(paths, *, max_bytes=10 * 1024 * 1024, encoding="auto", year=None,
            tz=timezone.utc, window_seconds=300, threshold=3):
    if not 1 <= max_bytes <= 100 * 1024 * 1024:
        raise ValueError("max_bytes must be between 1 and 104857600")
    if window_seconds <= 0 or threshold < 2:
        raise ValueError("window must be positive and threshold at least 2")
    if year is not None and not 1 <= year <= 9999:
        raise ValueError("year must be between 1 and 9999")
    if encoding != "auto":
        codecs.lookup(encoding)
    events, sources, warnings = [], [], []
    seen = set()
    total = 0
    for supplied in paths:
        path = Path(supplied).resolve(strict=True)
        if path in seen:
            raise ValueError("duplicate input file")
        seen.add(path)
        if path.suffix.lower() not in (".log", ".txt") and path.name not in ("secure", "syslog"):
            raise ValueError("input must be .log, .txt, secure or syslog")
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("input must be a regular file")
        if path.stat().st_size > max_bytes:
            raise ValueError("input exceeds size limit")
        # Bound actual bytes as well, in case the file grows after stat().
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("input exceeds size limit while reading")
        total += len(data)
        if total > max_bytes:
            raise ValueError("combined inputs exceed size limit")
        chosen = encoding
        if chosen == "auto":
            chosen = "utf-16" if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
        decoded = data.decode(chosen, errors="replace")
        if not isinstance(decoded, str):
            raise ValueError("encoding must be a text encoding")
        source = f"source-{len(sources) + 1}"
        counts = Counter()
        current_year, previous_month = year, None
        line_count = 0
        for number, line in enumerate(decoded.splitlines(), 1):
            line_count = number
            if len(line) > MAX_LINE:
                counts["oversized_lines_skipped"] += 1
                continue
            if "\ufffd" in line or "\x00" in line:
                counts["damaged_lines_skipped"] += 1
                continue
            old_style = SYSLOG.match(line)
            if old_style and current_year is not None:
                month = MONTHS.get(old_style[1])
                if previous_month == 12 and month == 1:
                    current_year += 1
                previous_month = month
            event = recognize(line)
            if event is None:
                if line.strip():
                    counts["unrecognized_lines"] += 1
                continue
            dt = timestamp(line, current_year, tz)
            if dt is None:
                counts["events_without_timestamp"] += 1
            event.update(source=source, line=number,
                         timestamp=dt.astimezone(timezone.utc) if dt else None, raw=line)
            events.append(event)
        sources.append(dict(id=source, path=str(path), bytes=len(data), encoding=chosen, lines=line_count,
                            diagnostics=dict(counts)))
        for reason, count in sorted(counts.items()):
            warnings.append(f"{source}: {reason}={count}")
    repeated = repetitions(events, window_seconds, threshold)
    for event in events:
        if event["timestamp"] is not None:
            event["timestamp"] = event["timestamp"].isoformat()
    return dict(schema_version=1, notice=NOTICE,
                settings=dict(year=year, timezone=str(tz), window_seconds=window_seconds,
                              threshold=threshold, max_bytes=max_bytes),
                sources=sources, summary=dict(Counter(e["rule"] for e in events)),
                unknown_user_events=sum(e["unknown_user"] for e in events),
                warnings=warnings, events=events, repetitions=repeated)
