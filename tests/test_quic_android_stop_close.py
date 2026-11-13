#!/usr/bin/env python3
"""Regression check: Service::stop() must stop QUIC endpoints even on Android."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def extract_function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    idx = opening + 1
    while depth > 0 and idx < len(source):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        idx += 1
    if depth != 0:
        raise AssertionError(f"Unbalanced braces in {signature}")
    return source[opening + 1 : idx - 1]


def check_service_stop(source: str) -> None:
    body = extract_function_body(source, "void Service::stop()")

    # Track preprocessor conditional stack; each entry is (directive_line, is_android_guard_active)
    pp_stack = []
    found_quic_client_stop = False
    found_quic_server_stop = False

    for lineno, raw_line in enumerate(body.splitlines(), start=1):
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            # Normalize whitespace after '#'
            directive = re.sub(r"^#\s*", "#", stripped)
            if re.match(r"^#(ifdef|ifndef|if)\b", directive):
                is_ifndef_android = bool(
                    re.match(r"^#ifndef\s+__ANDROID__\b", directive)
                )
                pp_stack.append((directive, is_ifndef_android))
            elif re.match(r"^#else\b", directive):
                if pp_stack:
                    prev_dir, prev_android = pp_stack[-1]
                    # Inside #else of #ifndef __ANDROID__, it's the __ANDROID__ branch
                    pp_stack[-1] = (prev_dir + " -> #else", False if prev_android else False)
            elif re.match(r"^#elif\b", directive):
                if pp_stack:
                    prev_dir, _ = pp_stack[-1]
                    pp_stack[-1] = (prev_dir + " -> " + directive, False)
            elif re.match(r"^#endif\b", directive):
                if not pp_stack:
                    raise AssertionError(f"Unmatched #endif at Service::stop() line {lineno}")
                pp_stack.pop()
            continue

        in_ifndef_android = any(is_android for _, is_android in pp_stack)
        if "m_quic_client->stop()" in stripped:
            found_quic_client_stop = True
            if in_ifndef_android:
                raise AssertionError(
                    f"m_quic_client->stop() is inside #ifndef __ANDROID__ at Service::stop() line {lineno}"
                )
        if "m_quic_server->stop()" in stripped:
            found_quic_server_stop = True
            if in_ifndef_android:
                raise AssertionError(
                    f"m_quic_server->stop() is inside #ifndef __ANDROID__ at Service::stop() line {lineno}"
                )

    if not found_quic_client_stop:
        raise AssertionError("m_quic_client->stop() not found in Service::stop()")
    if not found_quic_server_stop:
        raise AssertionError("m_quic_server->stop() not found in Service::stop()")


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "src/core/service.cpp"
    source = target.read_text(encoding="utf-8")
    check_service_stop(source)
    print(f"PASS: QUIC stop calls in {target} are outside #ifndef __ANDROID__")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
