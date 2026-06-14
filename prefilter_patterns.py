#!/usr/bin/env python3
"""Extract prefilter literals from all non-PathFullPattern patterns in a borg pattern file.

Parses every pattern that would go through the prefilter/automaton in patterns.py
(all styles except 'pf').  For each pattern, generates the internal regex, then
extracts prefilter literal groups.

Usage: python prefilter_patterns.py <pattern-file>
"""

import fnmatch
import importlib.util
import posixpath
import re
import sys

# Import pattern_extract_prefilter_literals directly, bypassing borg.patterns
spec = importlib.util.spec_from_file_location(
    "regex_literal", "src/borg/helpers/regex_literal.py"
)
regex_literal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(regex_literal)
pattern_extract_prefilter_literals = regex_literal.pattern_extract_prefilter_literals

# Import shellpattern.translate
spec = importlib.util.spec_from_file_location(
    "shellpattern", "src/borg/helpers/shellpattern.py"
)
shellpattern = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shellpattern)


def parse_pattern_line(line: str, current_default: str) -> tuple[str | None, str]:
    """Parse a borg pattern-file line.

    Returns (pattern_str_or_None, new_default).
    - P/p lines update the default pattern style.
    - R/r lines are root paths (ignored for prefilter purposes).
    - +/-/! lines are include/exclude patterns.
    """
    line = line.strip()
    if not line:
        return None, current_default

    cmd = line[0]
    remainder = line[1:].lstrip()

    if cmd in ("P", "p"):
        # Set default pattern style
        return None, remainder
    elif cmd in ("R", "r"):
        # Root path — not a pattern
        return None, current_default
    elif cmd in ("+", "-", "!"):
        return remainder, current_default
    else:
        # Unknown command — skip
        return None, current_default


def pattern_to_regex(pattern_body: str, style: str) -> str:
    """Convert a borg pattern to its internal regex, mirroring the _prepare
    methods of each PatternBase subclass in patterns.py.  Only covers the
    styles that participate in the prefilter (all except 'pf')."""
    if style == "fm":
        # Mirrors FnmatchPattern._prepare
        if pattern_body.endswith("/"):
            pattern_body = posixpath.normpath(pattern_body).rstrip("/") + "/*/"
        else:
            pattern_body = posixpath.normpath(pattern_body) + "/*"
        pattern_body = pattern_body.lstrip("/")
        return fnmatch.translate(pattern_body)
    elif style == "sh":
        # Mirrors ShellPattern._prepare
        if pattern_body.endswith("/"):
            pattern_body = posixpath.normpath(pattern_body).rstrip("/") + "?"
            match_end = r"\Z"
        else:
            pattern_body = posixpath.normpath(pattern_body) + r"/"
            match_end = ""
        pattern_body = pattern_body.lstrip("/")
        spattern = shellpattern.translate(pattern_body, match_end=match_end)
        regex_pattern = rf"{spattern[:5]}\A{spattern[5:]}"
        if regex_pattern.endswith("/"):
            regex_pattern = regex_pattern[:-1] + r"\Z"
        return regex_pattern
    elif style == "pp":
        # Mirrors PathPrefixPattern._prepare
        pattern_body = (posixpath.normpath(pattern_body).rstrip("/") + "/").lstrip("/")
        return r"\A" + re.escape(pattern_body)
    elif style == "re":
        # Mirrors RegexPattern._prepare — raw regex, no transformation
        return pattern_body
    else:
        raise ValueError(f"Unsupported pattern style: {style!r}")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pattern-file>", file=sys.stderr)
        sys.exit(1)

    pattern_file = sys.argv[1]
    default_style = "sh"  # borg's default for pattern files

    with open(pattern_file) as f:
        for lineno, raw_line in enumerate(f, 1):
            line = raw_line.rstrip("\n")
            # Skip empty lines and comments
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue

            pattern_str, default_style = parse_pattern_line(line, default_style)
            if pattern_str is None:
                continue

            # Determine effective style: explicit prefix or current default
            if len(pattern_str) > 2 and pattern_str[2] == ":" and pattern_str[:2].isalnum():
                style = pattern_str[:2]
                pattern_body = pattern_str[3:]
                uses_default = False
            else:
                style = default_style
                pattern_body = pattern_str
                uses_default = True

            # Skip PathFullPattern — it bypasses the prefilter in patterns.py
            if style == "pf":
                continue

            result = pattern_extract_prefilter_literals(pattern_to_regex(pattern_body, style))

            source = f"line {lineno} (default)" if uses_default else f"line {lineno} (explicit)"
            print(f"### {source}: {pattern_body!r}")
            if result is None:
                print("    No prefilter literals extracted")
            else:
                for i, group in enumerate(result):
                    print(f"    group {i}: {group}")
            print()


if __name__ == "__main__":
    main()
