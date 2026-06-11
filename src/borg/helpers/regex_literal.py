from re import _parser
import re as _re

# Matches top-level inline flags that include case-insensitive: (?i), (?im), (?i-s), etc.
# Does NOT match scoped groups like (?i:…), (?im:…).
_CI_TOPLEVEL_RE = _re.compile(r"^\(\?[a-z-]*i[a-z-]*\)")

# Expandable CATEGORY shorthand classes and their ASCII character ordinals.
# Only categories with ≤20 literals are included to keep expansions bounded.
# To add a new category: add one entry to this dict.
_CATEGORY_CHARS: dict = {
    _parser.CATEGORY_DIGIT: range(ord("0"), ord("9") + 1),  # 10 chars
    _parser.CATEGORY_SPACE: [ord(c) for c in " \t\n\r\f\v"],  #  6 chars
}


def pattern_extract_prefilter_literals(pattern: str, *, max_combinations: int = 20) -> list[list[str]] | None:
    """
    Extract prefilter groups from a regex pattern for accelerated
    multi-pattern matching.

    Returns a list of independent prefilter groups, each being a list of
    literal strings.  Every group is self-contained: for any string that
    matches the regex, at least one literal in that group is a substring.
    The caller picks **one** group as their prefilter, giving downstream
    code a choice of groups with different specificity / overlap
    characteristics.

    Returns None if no useful prefilter groups could be extracted.  This
    covers both unparseable patterns and valid patterns that contain no
    mandatory literal characters (e.g. ``r"\\d+"``, ``r"^[a-z]*$"``).

    **Phase 1 — Mandatory-literal-only groups**

    Each group consists of literals *guaranteed* to appear in every regex
    match.  Contiguous mandatory LITERAL nodes form singleton groups
    ``[s]``.  Segment boundaries (``.``, character classes, anchors,
    lookarounds, backreferences, optional repeats) break mandatory
    segments and flush the accumulator as a group.

    - **Alternation** ``(a|b)``: if there are no mandatory literals
      anywhere outside the alternation, the branch results form one group.
      Otherwise the alternation content is suppressed (external mandatory
      literals are sufficient).
    - **Character classes / anchors / metacharacters**: always break
      mandatory segments.
    - **Optional repeats** ``?``, ``*``, ``{0,n}``: inner content is
      skipped.
    - **Required repeats** ``+``, ``{n}``, ``{n,m}`` (n≥1): inner content
      is walked for mandatory literals.
    - **Lookarounds**: content is never mandatory (not part of the match).
    - **Case-insensitive flag** ``(?i)`` (top-level) and ``(?i:…)``
      (scoped): each mandatory literal is expanded into all case variants
      within its group, subject to *max_combinations* per group.

    **Phase 2 — Extended groups from alternations and optionals**

    Augments the Phase 1 mandatory groups with additional groups that
    combine mandatory parts with alternation branches, optional
    expansions, and character class alternatives.  These groups are
    *more specific* — they have fewer false positives — giving the
    downstream selector more options to minimize overlap.

    - **Alternation-including groups**: when an alternation has external
      mandatory literals, groups are produced that combine alternation
      branches with adjacent mandatory parts (prefix + branch, branch +
      suffix, or prefix + branch + suffix).
    - **Optional-expansion groups**: for optional constructs, groups are
      produced with and without the optional content combined with
      adjacent mandatory literals.

    When *max_combinations* is too tight for a particular group, that
    group is truncated but other groups still survive (the function never
    fails entirely because one group exceeded the budget).
    """
    if max_combinations <= 0:
        return None

    try:
        parsed = _parser.parse(pattern)
    except _parser.error:
        return None

    # Detect top-level case-insensitive flag: (?i), (?im), (?i-s), etc.
    has_case_insensitive = bool(_CI_TOPLEVEL_RE.match(pattern))

    # ---- Phase 1: collect mandatory literal segments ----

    # Each segment is (text, needs_ci_expansion).
    # needs_ci_expansion is True when the segment was accumulated inside
    # a scoped (?i:…) region (in addition to any top-level (?i) flag).
    segments: list[tuple[str, bool]] = []
    current: list[str] = []  # accumulator for current segment (list of chars)

    # Alternations saved for the "no mandatory outside" fallback case.
    # Each entry is (branches, flags, repeat_min, repeat_max) where
    # repeat_min/repeat_max come from an enclosing MAX_REPEAT if any
    # (default (1, 1) for unrepeated alternations).
    alternations: list[tuple[list, int, int, int]] = []
    # IN-based alternation repeats captured from MAX_REPEAT/MIN_REPEAT:
    # (prefix_before_repeat, in_char_strings, repeat_min, repeat_max)
    _in_alt_repeats: list[tuple[str, list[str], int, int]] = []
    # Prefixes that were consumed by an IN repeat — their Phase 1 segment
    # is redundant and should be skipped.
    _consumed_prefixes: set[str] = set()

    # ---- Phase 2: pending context tracking ----
    # When a BRANCH or optional construct is encountered with surrounding
    # mandatory context, we record a "pending" entry.  The prefix is known
    # immediately, but the suffix is collected from content that follows
    # the construct.  When the next boundary flushes the accumulator, the
    # pending entries are resolved with the flushed text as suffix.

    # Pending alternation contexts: (prefix, branch_literals)
    _pending_alt_ctx: list[tuple[str, list[str]]] = []
    # Pending alternation contexts inside a MAX_REPEAT/MIN_REPEAT:
    # (prefix, branch_literals, repeat_min, repeat_max)
    _pending_alt_repeat_ctx: list[tuple[str, list[str], int, int]] = []
    # Pending optional contexts: (prefix, optional_literal)
    _pending_opt_ctx: list[tuple[str, str]] = []
    # Pending shortened alternation contexts:
    # (prefix, pure_lits, prefix_lits, suffix_lits, core_lits)
    _pending_shortened_alt_ctx: list[tuple[str, list[str], list[str], list[str], list[str]]] = []
    # Resolved alternation contexts: (prefix, branch_literals, suffix)
    _alt_contexts: list[tuple[str, list[str], str]] = []
    # Resolved shortened alternation contexts:
    # (prefix, pure_lits, prefix_lits, suffix_lits, core_lits, suffix)
    _shortened_alt_contexts: list[tuple[str, list[str], list[str], list[str], list[str], str]] = []
    # Resolved alternation-repeat contexts:
    # (prefix, branch_literals, suffix, repeat_min, repeat_max)
    _alt_repeat_contexts: list[tuple[str, list[str], str, int, int]] = []
    # When set, the BRANCH handler stores to _pending_alt_repeat_ctx instead
    # of _pending_alt_ctx, and includes these repeat parameters.
    _inside_repeat: tuple[int, int] | None = None
    # Prefix captured before flushing in a MAX_REPEAT handler, for use by
    # the inner BRANCH handler to record the alternating context.
    _repeat_prefix: str = ""
    # Resolved optional contexts: (prefix, optional_literal, suffix)
    _opt_contexts: list[tuple[str, str, str]] = []
    # Lookaround-forced literals extracted from positive lookarounds (ASSERT).
    # Each is an independent prefilter group — literals guaranteed to appear
    # in the search string (not necessarily within the match span).
    _lookaround_groups: list[list[str]] = []
    # Pending lookbehind-forced literals (deferred merge with next flushed suffix).
    _pending_lookbehind_lits: list[str] | None = None
    # Cache of the most recent lookbehind+body merge (for triple merges).
    _lookbehind_body_merged: list[str] | None = None

    def _flush(ci: bool = False) -> None:
        nonlocal current, _pending_lookbehind_lits, _lookbehind_body_merged
        # Resolve any pending Phase 2 contexts with the current
        # accumulator as suffix BEFORE creating the segment.
        suffix = "".join(current)
        _resolve_pending_contexts(suffix)
        # Resolve pending lookbehind merge: lookbehind_lit + suffix.
        # Always clear _pending_lookbehind_lits after a flush so it
        # does not leak across separators (alternations, etc.) and
        # merge incorrectly with non-adjacent body literals.
        if _pending_lookbehind_lits:
            if suffix:
                merged = sorted(set(lb + suffix for lb in _pending_lookbehind_lits))
                _lookaround_groups.append(merged[:max_combinations])
                _lookbehind_body_merged = merged
            _pending_lookbehind_lits = None
        if current:
            segments.append((suffix, ci))
            current = []

    def _has_mandatory_outside_alt(node, inside_alt: bool = False) -> bool:
        """Check whether *node* contains any LITERAL outside alternations."""
        for opcode, value in node:
            if opcode is _parser.LITERAL:
                if not inside_alt:
                    return True
            elif opcode in (
                _parser.ANY,
                _parser.AT,
                _parser.IN,
                _parser.ASSERT,
                _parser.ASSERT_NOT,
                _parser.GROUPREF,
                _parser.GROUPREF_EXISTS,
            ):
                continue
            elif opcode is _parser.SUBPATTERN:
                _, _, _, inner = value
                if _has_mandatory_outside_alt(inner, inside_alt):
                    return True
            elif opcode is _parser.ATOMIC_GROUP:
                if _has_mandatory_outside_alt(value, inside_alt):
                    return True
            elif opcode is _parser.BRANCH:
                for branch in value[1]:
                    _has_mandatory_outside_alt(branch, True)
            elif opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                min_c, _, inner = value
                if min_c > 0:
                    if _has_mandatory_outside_alt(inner, inside_alt):
                        return True
        return False

    def _branch_literal_string(node) -> str | None:
        """Concatenate all LITERAL nodes in *node* into a single string.
        Returns None if *node* contains anything other than LITERAL, SUBPATTERN,
        ATOMIC_GROUP, or zero-width assertions (ASSERT, ASSERT_NOT, AT).

        Merges adjacent lookaround literals: a leading lookbehind ASSERT(-1)
        contributes its literal as a prefix; a trailing lookahead ASSERT(+1)
        contributes its literal as a suffix."""
        items = list(node)
        prefix = ""
        suffix = ""
        # Leading lookbehind → merge as prefix
        if items and items[0][0] is _parser.ASSERT:
            direction, inner = items[0][1]
            if direction == -1:  # lookbehind
                inner_lit = _branch_literal_string(inner)
                if inner_lit:
                    prefix = inner_lit
                items = items[1:]
        # Trailing lookahead → merge as suffix
        if items and items[-1][0] is _parser.ASSERT:
            direction, inner = items[-1][1]
            if direction == 1:  # lookahead
                inner_lit = _branch_literal_string(inner)
                if inner_lit:
                    suffix = inner_lit
                items = items[:-1]
        # Body
        chars: list[str] = []
        for opcode, value in items:
            if opcode is _parser.LITERAL:
                chars.append(chr(value))
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                # Zero-width assertions — skip, not part of the match literal
                continue
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                sub = _branch_literal_string(inner)
                if sub is None:
                    return None
                chars.append(sub)
            elif opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                # Required repeat of literal content — extract inner literal once
                min_c, _, inner = value
                if min_c > 0:
                    sub = _branch_literal_string(inner)
                    if sub is not None:
                        chars.append(sub)
                        continue
                return None
            else:
                return None  # non-LITERAL, non-skippable in branch
        body = "".join(chars) if chars else None
        if body is None:
            return None
        return prefix + body + suffix

    def _collect_branch_results(branches, flags: int) -> list[str]:
        """For a pure-alternation pattern (no mandatory outside), walk each
        branch and collect its concatenated literal string for the group.

        When a branch contains nested IN-optimised or BRANCH-based
        alternations (which _branch_literal_string cannot flatten to a
        single string), falls back to recursive expansion via
        _expand_branch_to_literals.

        If any branch is non-expandable (both _branch_literal_string and
        _expand_branch_to_literals return None), returns empty — we can't
        guarantee results across all branches."""
        results: list[str] = []
        for branch in branches:
            lit = _branch_literal_string(branch)
            if lit:
                results.append(lit)
            else:
                expanded = _expand_branch_to_literals(branch, max_results=max_combinations)
                # Treat [""] (only-empty-string) as no useful content —
                # the branch may have lookaround-forced literals instead.
                if expanded and expanded != [""]:
                    results.extend(expanded)
                else:
                    # #4: try extracting lookaround-forced literals from
                    # ASSERT nodes when body-literals are absent.
                    look_lits = _extract_branch_lookaround_literals(branch, max_results=max_combinations)
                    if look_lits:
                        results.extend(look_lits)
                    else:
                        return []  # non-expandable branch → can't guarantee coverage
        return sorted(set(results))

    def _expand_branch_to_literals(node, max_results: int | None = None) -> list[str] | None:
        """Recursively expand *node* into all possible literal strings,
        handling nested BRANCH (alternation) and expandable IN nodes.

        Merges adjacent lookaround literals: leading lookbehind ASSERT(-1)
        content is prepended; trailing lookahead ASSERT(+1) content is
        appended, both crossed with results from the body.

        Returns None if non-expandable content is encountered or if the
        intermediate expansion exceeds *max_results* (budget cap)."""
        items = list(node)
        prefix_lits: list[str] | None = None
        suffix_lits: list[str] | None = None
        # Leading lookbehind → prepend its literals
        if items and items[0][0] is _parser.ASSERT:
            direction, inner = items[0][1]
            if direction == -1:  # lookbehind
                inner_expanded = _expand_branch_to_literals(inner, max_results=max_results)
                if inner_expanded and "" not in inner_expanded:
                    prefix_lits = inner_expanded
                items = items[1:]
        # Trailing lookahead → append its literals
        if items and items[-1][0] is _parser.ASSERT:
            direction, inner = items[-1][1]
            if direction == 1:  # lookahead
                inner_expanded = _expand_branch_to_literals(inner, max_results=max_results)
                if inner_expanded and "" not in inner_expanded:
                    suffix_lits = inner_expanded
                items = items[:-1]
        results: list[str] = [""]
        for opcode, value in items:
            if opcode is _parser.LITERAL:
                results = [r + chr(value) for r in results]
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                continue
            elif opcode is _parser.IN:
                chars = _collect_in_expandable_chars(value)
                if not chars:
                    return None
                strs = [chr(c) for c in chars]
                results = [r + s for r in results for s in strs]
                if max_results is not None and len(results) > max_results:
                    return None
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                sub = _expand_branch_to_literals(inner, max_results=max_results)
                if sub is None:
                    return None
                results = [r + s for r in results for s in sub]
                if max_results is not None and len(results) > max_results:
                    return None
            elif opcode is _parser.BRANCH:
                branch_lits: list[str] = []
                for branch in value[1]:
                    sub = _expand_branch_to_literals(branch, max_results=max_results)
                    if sub is None:
                        return None  # non-expandable branch → can't guarantee results
                    branch_lits.extend(sub)
                if not branch_lits:
                    return None
                results = [r + s for r in results for s in branch_lits]
                if max_results is not None and len(results) > max_results:
                    return None
            elif opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                min_c, max_c, inner = value
                if min_c > 0 and max_c == 1:
                    # Only expand exact-once repeats (bare \d, not \d+ or \d{n})
                    # because larger repeats can't be enumerated correctly.
                    sub = _expand_branch_to_literals(inner, max_results=max_results)
                    if sub is not None:
                        results = [r + s for r in results for s in sub]
                        if max_results is not None and len(results) > max_results:
                            return None
                        continue
                return None
            else:
                return None
        # Apply prefix/suffix lookaround merges
        if prefix_lits:
            results = [p + r for p in prefix_lits for r in results]
            if max_results is not None and len(results) > max_results:
                return None
        if suffix_lits:
            results = [r + s for r in results for s in suffix_lits]
            if max_results is not None and len(results) > max_results:
                return None
        return results

    def _extract_branch_lookaround_literals(branch, max_results: int | None = None) -> list[str] | None:
        """Extract forced literals from all positive lookaround (ASSERT) nodes
        within *branch*.  Recursively enters SUBPATTERN and ATOMIC_GROUP.
        Returns a list of guaranteed literals (sorted, deduplicated), or None
        if no forced literals were found or extraction failed.

        Only ASSERT (positive lookaround) nodes are inspected; ASSERT_NOT
        (negative lookaround) nodes are skipped because they enforce absence,
        not presence."""
        results: list[str] = []
        for opcode, value in branch:
            if opcode is _parser.ASSERT:
                _direction, inner_ast = value
                lits = _expand_branch_to_literals(inner_ast, max_results=max_results)
                if lits and "" not in lits:
                    results.extend(lits)
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                sub = _extract_branch_lookaround_literals(inner, max_results=max_results)
                if sub:
                    results.extend(sub)
        return sorted(set(results)) if results else None

    # ---- Branch shortening (strip expansible edges) ----

    def _is_nonliteral_strippable(opcode, value) -> bool:
        """Check whether a single AST item is non-literal expansible
        content that can be stripped from the edge of a branch.

        An item is strippable if it matches variable/unbounded content:
        - IN / ANY (character class, not a fixed literal)
        - MAX_REPEAT/MIN_REPEAT where the repeat max is >1 or unbounded
          (e.g. +, *, {n,}, {n,m} with m>n)
        - SUBPATTERN/ATOMIC_GROUP containing strippable content."""
        if opcode is _parser.IN or opcode is _parser.ANY:
            return True
        if opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
            min_c, max_c, inner = value
            # A repeat is strippable if its max is unbounded (>1 repetition
            # possible) OR if the inner itself is expansible.
            if max_c != 1:
                return True
            # max_c == 1: check inner for expansible content
            return _contains_strippable(inner)
        if opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
            inner = value[3] if opcode is _parser.SUBPATTERN else value
            return _contains_strippable(inner)
        return False

    def _contains_strippable(node) -> bool:
        """Check whether *node* contains any strippable non-literal content."""
        for opcode, value in node:
            if _is_nonliteral_strippable(opcode, value):
                return True
            if opcode is _parser.BRANCH:
                # BRANCH itself is not strippable, but check its branches
                for branch in value[1]:
                    if _contains_strippable(branch):
                        return True
        return False

    def _walk_literal_prefix(items):
        """Walk *items* from the left, collecting literal characters.
        Stops at the first item that is non-literal AND non-zero-width.
        Returns (prefix_string, stop_index).
        stop_index is len(items) if all items were consumed."""
        chars: list[str] = []
        for idx, (opcode, value) in enumerate(items):
            if opcode is _parser.LITERAL:
                chars.append(chr(value))
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                # Zero-width — skip, don't stop
                continue
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                inner_prefix, inner_stop = _walk_literal_prefix(inner)
                if inner_stop < len(inner):
                    # Inner has non-literal → stop at this item
                    return "".join(chars), idx
                if inner_prefix:
                    chars.append(inner_prefix)
            else:
                # Non-literal, non-zero-width → stop
                return "".join(chars), idx
        return "".join(chars), len(items)

    def _walk_literal_suffix(items):
        """Walk *items* from the right, collecting literal characters
        in reverse.  Stops at the first item that is non-literal AND
        non-zero-width.
        Returns (suffix_string, stop_index).
        stop_index is -1 if all items were consumed."""
        chars: list[str] = []
        for idx in range(len(items) - 1, -1, -1):
            opcode, value = items[idx]
            if opcode is _parser.LITERAL:
                chars.append(chr(value))
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                continue
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                inner_suffix, inner_stop = _walk_literal_suffix(inner)
                if inner_stop >= 0:
                    return "".join(reversed(chars)), idx
                if inner_suffix:
                    chars.append(inner_suffix)
            else:
                return "".join(reversed(chars)), idx
        return "".join(reversed(chars)), -1

    def _try_extract_in_from_item(item) -> list[int] | None:
        """Try to extract expandable IN characters from an AST item.
        Only returns characters for LITERAL-based INs (not CATEGORY/RANGE).
        Unwraps MAX_REPEAT/MIN_REPEAT/SUBPATTERN/ATOMIC_GROUP wrappers.
        Returns list of char ordinals or None."""
        opcode, value = item
        # Unwrap repeat wrappers
        if opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
            _, _, inner = value
            if len(inner) == 1 and inner[0][0] is _parser.IN:
                return _collect_literal_in_chars(inner[0][1])
            # Unwrap nested SUBPATTERN/ATOMIC_GROUP inside repeat
            if len(inner) == 1 and inner[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                sub_op, sub_val = inner[0]
                sub_inner = sub_val[3] if sub_op is _parser.SUBPATTERN else sub_val
                if len(sub_inner) == 1 and sub_inner[0][0] is _parser.IN:
                    return _collect_literal_in_chars(sub_inner[0][1])
            return None
        # Unwrap SUBPATTERN/ATOMIC_GROUP
        if opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
            inner = value[3] if opcode is _parser.SUBPATTERN else value
            if len(inner) == 1:
                return _try_extract_in_from_item(inner[0])
            return None
        # Direct IN
        if opcode is _parser.IN:
            return _collect_literal_in_chars(value)
        return None

    def _collect_literal_in_chars(in_value) -> list[int] | None:
        """Like _collect_in_expandable_chars but only returns characters
        for LITERAL-only IN (no CATEGORY, no RANGE, no NEGATE)."""
        chars: list[int] = []
        for opcode, val in in_value:
            if opcode is _parser.LITERAL:
                chars.append(val)
            else:
                # CATEGORY, RANGE, NEGATE — not a pure-literal class
                return None
        return chars if chars else None

    def _extract_inner_literal_cores(items) -> list[str] | None:
        """Extract guaranteed literal cores from *items* which may contain
        BRANCH, expandable IN, or LITERAL content between expansible edges.

        Returns a list of literal strings, or None if no core is found."""
        if not items:
            return [""]

        # Strip leading expansible, but keep MAX_REPEATs with expandable
        # IN chars as potential cores (they're at a fixed edge position).
        start = 0
        while start < len(items):
            opcode, value = items[start]
            if opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                start += 1
                continue
            # If this item has an expandable IN, keep it (it's a core candidate)
            if _try_extract_in_from_item(items[start]) is not None:
                break
            if _is_nonliteral_strippable(opcode, value):
                start += 1
                continue
            break
        end = len(items) - 1
        while end >= start:
            opcode, value = items[end]
            if opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                end -= 1
                continue
            if _try_extract_in_from_item(items[end]) is not None:
                break
            if _is_nonliteral_strippable(opcode, value):
                end -= 1
                continue
            break

        core_items = items[start : end + 1]
        if not core_items:
            return None

        # Check for single expandable IN at the core (edge case: all that
        # remains is a MAX_REPEAT/IN with expandable chars)
        if len(core_items) == 1:
            chars = _try_extract_in_from_item(core_items[0])
            if chars:
                return [chr(c) for c in chars]

        # Check for BRANCH — the literal core is the nested alternation.
        # First, check for a single SUBPATTERN/ATOMIC_GROUP wrapping everything.
        branch_items = core_items
        while len(branch_items) == 1 and branch_items[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
            opcode, value = branch_items[0]
            branch_items = value[3] if opcode is _parser.SUBPATTERN else value

        # Look for BRANCH in the (possibly unwrapped) items.
        # Also check inside individual SUBPATTERN/ATOMIC_GROUP items.
        branch_opcode = None
        branch_value = None
        branch_idx = -1
        for i, (opcode, value) in enumerate(branch_items):
            if opcode is _parser.BRANCH:
                branch_opcode = opcode
                branch_value = value
                branch_idx = i
                break
            if opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                if len(inner) == 1 and inner[0][0] is _parser.BRANCH:
                    branch_opcode = _parser.BRANCH
                    branch_value = inner[0][1]
                    branch_idx = i
                    break
        if branch_opcode is _parser.BRANCH:
            branch_cores: list[str] = []
            for branch in branch_value[1]:
                result = _shorten_branch_literals(branch)
                if result is None:
                    return None
                branch_lits, _ls, _ts, _split_trailing = result
                branch_cores.extend(branch_lits)
            # If the BRANCH has items before/after it in core_items,
            # those are literal prefixes/suffixes to each branch result.
            if prefix_items := branch_items[:branch_idx]:
                pfx = "".join(_collect_literal_chars_from_items(prefix_items))
                branch_cores = [pfx + c for c in branch_cores]
            if suffix_items := branch_items[branch_idx + 1 :]:
                sfx = "".join(_collect_literal_chars_from_items(suffix_items))
                branch_cores = [c + sfx for c in branch_cores]
            return sorted(set(branch_cores)) if branch_cores else None

        # Check for expandable IN (also unwrap SUBPATTERN/ATOMIC_GROUP/MAX_REPEAT)
        if len(core_items) == 1:
            opcode, value = core_items[0]
            inner = None
            if opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                _, _, inner = value
                if len(inner) == 1 and inner[0][0] is _parser.IN:
                    chars = _collect_in_expandable_chars(inner[0][1])
                    if chars:
                        return sorted(set(chr(c) for c in chars))
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                # Unwrap nested SUBPATTERN/ATOMIC_GROUP to find IN or BRANCH
                while len(inner) == 1 and inner[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                    iv = inner[0]
                    inner = iv[1][3] if iv[0] is _parser.SUBPATTERN else iv[1]
                if len(inner) == 1 and inner[0][0] is _parser.IN:
                    chars = _collect_in_expandable_chars(inner[0][1])
                    if chars:
                        return sorted(set(chr(c) for c in chars))
                # Also check for MAX_REPEAT wrapping IN inside SUBPATTERN
                if len(inner) == 1 and inner[0][0] in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                    _, _, inner2 = inner[0][1]
                    if len(inner2) == 1 and inner2[0][0] is _parser.IN:
                        chars = _collect_in_expandable_chars(inner2[0][1])
                        if chars:
                            return sorted(set(chr(c) for c in chars))
            if opcode is _parser.IN:
                chars = _collect_in_expandable_chars(value)
                if chars:
                    return sorted(set(chr(c) for c in chars))

        # Fallback: collect any literal characters
        lits = _collect_literal_chars_from_items(core_items)
        if lits:
            return ["".join(lits)]
        return None

    def _collect_literal_chars_from_items(items):
        """Collect all LITERAL characters from *items*, recursively
        entering SUBPATTERN/ATOMIC_GROUP.  Skips zero-width assertions."""
        chars: list[str] = []
        for opcode, value in items:
            if opcode is _parser.LITERAL:
                chars.append(chr(value))
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                continue
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                chars.extend(_collect_literal_chars_from_items(inner))
        return chars

    def _shorten_branch_literals(node) -> tuple[list[str], bool, bool, list[str] | None] | None:
        """Extract guaranteed literal substrings from a branch *node*
        after stripping leading and trailing expansible content.

        Returns (literals, leading_shortened, trailing_shortened, split_trailing_lits)
        or None if no literal core can be found.

        - leading_shortened: True if leading expansible content was stripped.
        - trailing_shortened: True if trailing expansible content was stripped.
        - split_trailing_lits: when set, these are trailing-side cores that
          attach to the suffix only (leading IS shortened by expansible middle).
          Used for the split-core case where literal content exists on both
          sides of expansible middle content (e.g. opq.+rst yields ['opq']
          as primary and ['rst'] as split_trailing_lits).

        A "shortened" flag being True means the literal result's position
        relative to external prefix/suffix is uncertain on that side."""
        items = list(node)
        leading_prefix, left_stop = _walk_literal_prefix(items)
        trailing_suffix, right_stop = _walk_literal_suffix(items)

        # Determine if leading/trailing edges had expansible content.
        # leading_shortened: True if the literal content does NOT start at
        #   position 0 — i.e. there was expansible content on the left.
        # trailing_shortened: True if the literal content does NOT extend
        #   to the end — i.e. there was expansible content on the right.
        #
        # If leading_prefix is empty, the walk stopped immediately at
        # non-literal content → leading was shortened.
        # If trailing_suffix is empty, the right walk stopped immediately
        # at non-literal content → trailing was shortened.
        #
        # Exception: if left_stop > right_stop the walks overlapped
        # (pure literal branch).
        if left_stop > right_stop:
            return [leading_prefix], False, False, None
        # leading_shortened: True if there was expansible content on the
        # leading edge that was stripped.  A BRANCH at the leading edge
        # is NOT "shortened" — it's the literal core (nested alternation).
        # A MAX_REPEAT with expandable LITERAL-based IN is also NOT
        # shortened — the chars are the core at a fixed position.
        leading_shortened = False
        if leading_prefix == "" and left_stop < len(items):
            stop_item = items[left_stop]
            stop_opcode = stop_item[0]
            if stop_opcode is not _parser.BRANCH:
                # Check if the stop item has an expandable LITERAL IN
                # (which becomes the core — not shortened)
                if _try_extract_in_from_item(stop_item) is not None:
                    leading_shortened = False
                else:
                    # Unwrap to check for BRANCH
                    inner_check = [stop_item]
                    while len(inner_check) == 1 and inner_check[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                        op, val = inner_check[0]
                        inner_check = val[3] if op is _parser.SUBPATTERN else val
                    if not any(op is _parser.BRANCH for op, _ in inner_check):
                        leading_shortened = True
        trailing_shortened = False
        if trailing_suffix == "" and right_stop >= 0:
            stop_item = items[right_stop]
            stop_opcode = stop_item[0]
            if stop_opcode is not _parser.BRANCH:
                if _try_extract_in_from_item(stop_item) is not None:
                    trailing_shortened = False
                else:
                    inner_check = [stop_item]
                    while len(inner_check) == 1 and inner_check[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                        op, val = inner_check[0]
                        inner_check = val[3] if op is _parser.SUBPATTERN else val
                    if not any(op is _parser.BRANCH for op, _ in inner_check):
                        trailing_shortened = True

        # Extract middle items (between where left and right walks stopped)
        middle = items[left_stop : right_stop + 1]

        # If middle is empty, just return leading+trailing
        if not middle:
            result = leading_prefix + trailing_suffix
            if not result:
                return None
            return [result], leading_shortened, trailing_shortened, None

        # Extract literal cores from the middle
        inner_lits = _extract_inner_literal_cores(middle)
        if inner_lits is None:
            # No core found in middle.
            # Split-core detection: when there is literal content on BOTH
            # sides of expansible-only middle content, the two literal parts
            # must be produced as SEPARATE results.
            #   e.g. opq.+rst → ['opq'] (prefix_lits) + ['rst'] (suffix_lits)
            # Concatenating them (opqrst) is NOT valid.
            if leading_prefix and trailing_suffix:
                # Leading part attaches to prefix (trailing IS shortened
                # by the expansible middle).
                # Trailing part attaches to suffix (leading IS shortened
                # by the expansible middle).
                return [leading_prefix], False, True, [trailing_suffix]
            result = leading_prefix + trailing_suffix
            if not result:
                return None
            return [result], leading_shortened, trailing_shortened, None

        # Combine leading + each core + trailing
        # Filter out empty strings from inner_lits
        effective_inner = [c for c in inner_lits if c]
        if not effective_inner:
            result = leading_prefix + trailing_suffix
            if not result:
                return None
            return [result], leading_shortened, trailing_shortened, None

        results = [leading_prefix + c + trailing_suffix for c in effective_inner]
        return sorted(set(results)), leading_shortened, trailing_shortened, None

    def _collect_branch_results_shortened(branches, flags: int):
        """Like _collect_branch_results but falls back to branch shortening
        when branches contain expansible content.

        Returns (pure_lits, prefix_lits, suffix_lits, core_lits) where:
        - pure_lits: combine with BOTH prefix and suffix
        - prefix_lits: combine with PREFIX only (trailing shortened)
        - suffix_lits: combine with SUFFIX only (leading shortened)
        - core_lits: combine with NEITHER (both sides shortened)

        Returns None if no results could be produced at all."""
        pure: list[str] = []
        prefix_only: list[str] = []
        suffix_only: list[str] = []
        core_only: list[str] = []

        for branch in branches:
            # Try pure literal first
            lit = _branch_literal_string(branch)
            if lit:
                pure.append(lit)
                continue

            # Try shortening
            shortened = _shorten_branch_literals(branch)
            if shortened is None:
                # Try expansion as last resort
                expanded = _expand_branch_to_literals(branch, max_results=max_combinations)
                if expanded and expanded != [""]:
                    pure.extend(expanded)
                else:
                    # Try lookaround extraction
                    look_lits = _extract_branch_lookaround_literals(branch, max_results=max_combinations)
                    if look_lits:
                        pure.extend(look_lits)
                    else:
                        return None  # can't guarantee coverage
                continue

            lits, leading_short, trailing_short, split_trailing_lits = shortened
            if not lits:
                return None
            if leading_short and trailing_short:
                core_only.extend(lits)
            elif leading_short:
                suffix_only.extend(lits)
            elif trailing_short:
                prefix_only.extend(lits)
            else:
                pure.extend(lits)
            if split_trailing_lits:
                suffix_only.extend(split_trailing_lits)

        return (
            sorted(set(pure)) if pure else [],
            sorted(set(prefix_only)) if prefix_only else [],
            sorted(set(suffix_only)) if suffix_only else [],
            sorted(set(core_only)) if core_only else [],
        )

    def _optional_literal_string(node) -> str | None:
        """Like _branch_literal_string but for the inner content of an
        optional construct.  Concatenates all LITERAL nodes, skipping
        zero-width assertions."""
        chars: list[str] = []
        for opcode, value in node:
            if opcode is _parser.LITERAL:
                chars.append(chr(value))
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                continue
            elif opcode in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
                inner = value[3] if opcode is _parser.SUBPATTERN else value
                sub = _optional_literal_string(inner)
                if sub is None:
                    return None
                chars.append(sub)
            else:
                return None  # non-literal content in optional
        return "".join(chars) if chars else None

    def _collect_in_expandable_chars(in_value) -> list[int] | None:
        """Check whether *in_value* (contents of an IN opcode) is an
        expandable character class — all LITERAL entries, no NEGATE,
        no non-expandable RANGE/CATEGORY.  Returns the list of character
        ordinals if expandable (≤20 chars total), None otherwise."""
        chars: list[int] = []
        for opcode, val in in_value:
            if opcode is _parser.LITERAL:
                chars.append(val)
            elif opcode is _parser.NEGATE:
                return None
            elif opcode is _parser.CATEGORY:
                cat_chars = _CATEGORY_CHARS.get(val)
                if cat_chars is None:
                    return None
                chars.extend(cat_chars)
            elif opcode is _parser.RANGE:
                start, end = val
                span = end - start + 1
                if span > 20:
                    return None
                chars.extend(range(start, end + 1))
            else:
                return None
        if not chars or len(chars) > 20:
            return None
        return chars

    def _resolve_pending_contexts(suffix: str) -> None:
        """Move all pending contexts to resolved, using *suffix* as the suffix."""
        for prefix, branch_lits in _pending_alt_ctx:
            _alt_contexts.append((prefix, branch_lits, suffix))
        _pending_alt_ctx.clear()
        for prefix, pure_lits, prefix_lits, suffix_lits, core_lits in _pending_shortened_alt_ctx:
            _shortened_alt_contexts.append((prefix, pure_lits, prefix_lits, suffix_lits, core_lits, suffix))
        _pending_shortened_alt_ctx.clear()
        for prefix, branch_lits, rep_min, rep_max in _pending_alt_repeat_ctx:
            _alt_repeat_contexts.append((prefix, branch_lits, suffix, rep_min, rep_max))
        _pending_alt_repeat_ctx.clear()
        for prefix, opt_lit in _pending_opt_ctx:
            _opt_contexts.append((prefix, opt_lit, suffix))
        _pending_opt_ctx.clear()

    def _expand_repeat_combinations(items: list[str], repeat_min: int, repeat_max: int, budget: int) -> list[str]:
        """Generate cross-product combinations of *items* repeated
        *repeat_min* times, capped at *budget*."""
        if not items or repeat_min < 1:
            return []
        # Start with empty string (0 repetitions)
        current: list[str] = [""]
        results: list[str] = []
        for rep in range(1, repeat_min + 1):
            next_set: set[str] = set()
            for prefix in current:
                for item in items:
                    combo = prefix + item
                    if len(results) + len(next_set) + 1 >= budget:
                        next_set.add(combo)
                        break
                    next_set.add(combo)
                if len(results) + len(next_set) >= budget:
                    break
            if rep >= repeat_min:
                results.extend(sorted(next_set))
            current = sorted(next_set)
            if len(results) >= budget:
                break
        return sorted(set(results))[:budget]

    def _is_pure_alternation(node) -> bool:
        """Check whether *node* contains exactly one BRANCH and nothing
        else of significance (only zero-width assertions are ignored).
        Unwraps SUBPATTERN/ATOMIC_GROUP wrappers."""
        # Unwrap outer SUBPATTERN / ATOMIC_GROUP layers
        n = node
        while len(n) == 1 and n[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
            opcode, value = n[0]
            n = value[3] if opcode is _parser.SUBPATTERN else value
        has_branch = False
        for opcode, value in n:
            if opcode is _parser.BRANCH:
                if has_branch:
                    return False  # multiple BRANCH nodes
                has_branch = True
            elif opcode is _parser.IN:
                # Expandable IN (all single-char LITERAL) is like an alternation
                if has_branch or not _collect_in_expandable_chars(value):
                    return False
                has_branch = True
            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT, _parser.AT):
                continue
            else:
                return False  # other content (ANY, MAX_REPEAT, etc.)
        return has_branch

    def _extract_expandable_in_chars(node) -> list[str] | None:
        """Unwrap SUBPATTERN/ATOMIC_GROUP from *node* and return the
        character string list of a single expandable IN, or None."""
        n = node
        while len(n) == 1 and n[0][0] in (_parser.SUBPATTERN, _parser.ATOMIC_GROUP):
            opcode, val = n[0]
            n = val[3] if opcode is _parser.SUBPATTERN else val
        for opcode, val in n:
            if opcode is _parser.IN:
                chars = _collect_in_expandable_chars(val)
                return [chr(c) for c in chars] if chars else None
        return None

    def _expand_case_variants(lit: str, budget: int) -> list[str]:
        """Generate case-insensitive variants of *lit* (up to *budget*)."""
        alpha_positions = [i for i, c in enumerate(lit) if c.isalpha()]
        total = 1 << len(alpha_positions)
        results: list[str] = []
        limit = min(total, budget)
        for mask in range(limit):
            chars = list(lit)
            for j, pos in enumerate(alpha_positions):
                if mask & (1 << j):
                    chars[pos] = chars[pos].upper()
                else:
                    chars[pos] = chars[pos].lower()
            results.append("".join(chars))
        return sorted(set(results))

    has_mandatory = _has_mandatory_outside_alt(parsed)

    def walk(node, flags: int = 0, inside_alt: bool = False, inside_ci: bool = False) -> None:
        nonlocal current, _pending_lookbehind_lits, _lookbehind_body_merged
        nonlocal _inside_repeat, _pending_alt_repeat_ctx, _repeat_prefix
        for opcode, value in node:
            if opcode is _parser.LITERAL:
                current.append(chr(value))

            elif opcode is _parser.IN:
                # Character classes break mandatory segments.
                # Phase 2: if the class is expandable (all LITERAL,
                # no ranges/negation) and we have surrounding mandatory
                # context, record a pending context for later group
                # generation.  When prefix is empty (pattern starts with
                # an expandable class), skip the flush and record the
                # pending entry so the suffix can accumulate after it.
                prefix = "".join(current)
                chars = _collect_in_expandable_chars(value)
                if chars:
                    if prefix:
                        _flush(inside_ci)
                    _pending_alt_ctx.append((prefix, [chr(c) for c in chars]))
                else:
                    _flush(inside_ci)

            elif opcode in (_parser.ANY, _parser.AT):
                _flush(inside_ci)

            elif opcode is _parser.ASSERT:
                # Positive lookaround — content is never part of the match body,
                # but forces specific substrings to appear somewhere in the
                # search string.  Extract them as an independent group.
                #
                # Adjacent-literal merging:
                # - Lookahead (+1): lookahead content follows the prefix
                #   (what was just flushed).  Merge prefix + lookahead.
                # - Lookbehind (-1): lookbehind content precedes the suffix
                #   (what will be flushed next).  Defer merge until next flush.
                _flush(inside_ci)
                _direction, inner_ast = value
                look_lits = _expand_branch_to_literals(inner_ast, max_results=max_combinations)
                if look_lits:
                    # If any branch produced an empty string, the lookaround
                    # doesn't guarantee any specific literal — skip it.
                    if "" in look_lits:
                        pass
                    else:
                        effective = look_lits[:max_combinations]
                        if has_case_insensitive or inside_ci:
                            all_variants: list[str] = []
                            for lit in effective:
                                all_variants.extend(_expand_case_variants(lit, max_combinations))
                            effective = sorted(set(all_variants))[:max_combinations] if all_variants else effective
                        # Emit standalone lookaround group (#3)
                        _lookaround_groups.append(effective)
                        # Merge with adjacent literal context
                        if _direction == 1:  # lookahead → prefix + lookahead
                            if segments and segments[-1][0]:
                                prefix_text = segments[-1][0]
                                merged = sorted(set(prefix_text + la for la in effective))
                                _lookaround_groups.append(merged[:max_combinations])
                                # Triple merge: lookbehind + body + lookahead
                                if _lookbehind_body_merged:
                                    triple = sorted(set(lb + la for lb in _lookbehind_body_merged for la in effective))
                                    _lookaround_groups.append(triple[:max_combinations])
                                _lookbehind_body_merged = None
                        else:  # lookbehind (-1) → defer merge with suffix
                            _pending_lookbehind_lits = effective
            elif opcode is _parser.ASSERT_NOT:
                # Negative lookaround — enforces absence, not presence
                _flush(inside_ci)

            elif opcode in (_parser.GROUPREF, _parser.GROUPREF_EXISTS):
                _flush(inside_ci)

            elif opcode is _parser.SUBPATTERN:
                _, add_flags, _, inner = value
                sub_ci = inside_ci or bool(add_flags & _parser.SRE_FLAG_IGNORECASE)
                if sub_ci != inside_ci:
                    # Entering/leaving a CI scope — flush before so the
                    # outer non-CI content stays separate.
                    _flush(inside_ci)
                walk(inner, flags, inside_alt=inside_alt, inside_ci=sub_ci)
                if sub_ci != inside_ci:
                    # Leaving CI scope — flush the CI-scoped content with
                    # CI expansion flag set.
                    _flush(sub_ci)

            elif opcode is _parser.ATOMIC_GROUP:
                walk(value, flags, inside_alt=inside_alt, inside_ci=inside_ci)

            elif opcode is _parser.BRANCH:
                branches = value[1]
                # Phase 2: if there are mandatory literals outside this
                # alternation, record a pending context so we can later
                # produce combined prefix + branch + suffix groups.
                prefix = _repeat_prefix if _inside_repeat else "".join(current)
                branch_lits = _collect_branch_results(branches, flags)
                # For Phase 2, also check for empty branches (e.g. (a|)b).
                # An empty branch means the alternation may match nothing,
                # so the combined groups must include the "without branch"
                # variant.
                has_empty_branch = any(len(b) == 0 for b in branches)
                _flush(inside_ci)  # alternation itself is a boundary
                if has_mandatory and branch_lits:
                    # Include an empty string for empty branches so
                    # combined groups cover both cases.
                    if _inside_repeat:
                        rep_min, rep_max = _inside_repeat
                        if has_empty_branch:
                            _pending_alt_repeat_ctx.append((prefix, [*branch_lits, ""], rep_min, rep_max))
                        else:
                            _pending_alt_repeat_ctx.append((prefix, branch_lits, rep_min, rep_max))
                    else:
                        if has_empty_branch:
                            _pending_alt_ctx.append((prefix, [*branch_lits, ""]))
                        else:
                            _pending_alt_ctx.append((prefix, branch_lits))
                elif has_mandatory:
                    # Try branch shortening when _collect_branch_results returns empty
                    # due to expansible content (not just empty branches).
                    # Only use shortening if at least one non-empty branch has
                    # expansible content that _branch_literal_string can't handle.
                    needs_shortening = any(len(b) > 0 and _branch_literal_string(b) is None for b in branches)
                    if needs_shortening:
                        shortened = _collect_branch_results_shortened(branches, flags)
                        if shortened is not None:
                            pure_lits, prefix_lits, suffix_lits, core_lits = shortened
                            if pure_lits or prefix_lits or suffix_lits or core_lits:
                                if has_empty_branch:
                                    pure_lits = sorted(set(pure_lits + [""]))
                                _pending_shortened_alt_ctx.append(
                                    (prefix, pure_lits, prefix_lits, suffix_lits, core_lits)
                                )
                alternations.append((branches, flags, 1, 1))

            elif opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                min_c, max_c, inner = value
                if min_c == 0:
                    # Optional — content is not mandatory for Phase 1.
                    # Phase 2: record pending context with prefix + optional
                    # inner literal so we can produce expanded groups — but
                    # only when max_c == 1 (i.e. ? or {0,1}).  For unbounded
                    # repeats (*, {0,}, {0,n≥2}) the inner literal may repeat
                    # multiple times, so a simple with/without expansion is
                    # not valid.
                    prefix = "".join(current)
                    opt_lit = _optional_literal_string(inner)
                    _flush(inside_ci)
                    if prefix and opt_lit and max_c == 1:
                        _pending_opt_ctx.append((prefix, opt_lit))
                else:
                    # Required repeat — inner content is mandatory, but the
                    # repeat itself is a boundary (repeated content cannot
                    # be concatenated with neighbouring literals).
                    prefix_before = "".join(current)
                    _flush(inside_ci)
                    # If the inner is a grouped single-char alternation
                    # like (a|b|c){2} (parsed as SUBPATTERN wrapping an
                    # expandable IN, not a bare character class [abc]+),
                    # record it for cross-product expansion later.
                    in_chars = None
                    if (min_c > 1 or max_c > 1) and len(inner) == 1:
                        if inner[0][0] is _parser.SUBPATTERN:
                            in_chars = _extract_expandable_in_chars(inner)
                    if in_chars:
                        _in_alt_repeats.append((prefix_before, in_chars, min_c, max_c))
                        if prefix_before:
                            _consumed_prefixes.add(prefix_before)
                    # If the inner is a pure alternation, record repeat params
                    # so Phase 2 can generate cross-products / anchor-pairs.
                    _inside_repeat = (min_c, max_c)
                    _repeat_prefix = prefix_before
                    walk(inner, flags, inside_alt=inside_alt, inside_ci=inside_ci)
                    _repeat_prefix = ""
                    _inside_repeat = None
                    # Save and restore pending repeat ctx around flush to
                    # prevent premature resolution (suffix not yet accumulated).
                    saved_repeat = _pending_alt_repeat_ctx.copy()
                    _pending_alt_repeat_ctx.clear()
                    _flush(inside_ci)
                    _pending_alt_repeat_ctx = saved_repeat

    walk(parsed)
    _flush()  # flush any remaining segment / resolve remaining pending contexts

    # ---- Build groups ----
    groups: list[list[str]] = []

    # Phase 1: groups from mandatory segments
    if segments:
        for seg_text, seg_ci in segments:
            if seg_text in _consumed_prefixes:
                continue  # subsumed by an IN-based alternation repeat
            needs_ci = has_case_insensitive or seg_ci
            if needs_ci:
                variants = _expand_case_variants(seg_text, max_combinations)
                if variants:
                    groups.append(variants)
            else:
                groups.append([seg_text])
    elif not has_mandatory:
        # No mandatory segments found — try alternation fallback.
        # A pure alternation with no external mandatory literals forms
        # one group containing all branch results.
        if alternations:
            # Use only the outermost alternation (others are nested inside it)
            outer_branches, outer_flags, _rep_min, _rep_max = alternations[0]
            branch_lits = _collect_branch_results(outer_branches, outer_flags)
            if not branch_lits:
                # Try branch shortening for non-expandable, non-pure-literal branches
                shortened = _collect_branch_results_shortened(outer_branches, outer_flags)
                if shortened is not None:
                    pure_lits, prefix_lits, suffix_lits, core_lits = shortened
                    all_shortened = sorted(set(pure_lits + prefix_lits + suffix_lits + core_lits))
                    if all_shortened:
                        branch_lits = all_shortened
            if branch_lits:
                # Check whether the entire pattern is a repeat wrapping
                # a pure alternation, e.g. (foo|bar){2}.  In that case
                # expand the branch literals into cross-products.
                repeat_expanded = False
                if len(parsed) == 1 and parsed[0][0] in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                    min_c, max_c, inner_repeat = parsed[0][1]
                    if min_c > 1 or max_c > 1:
                        if _is_pure_alternation(inner_repeat):
                            expanded = _expand_repeat_combinations(branch_lits, min_c, max_c, max_combinations)
                            if expanded:
                                groups.append(expanded)
                                repeat_expanded = True
                        else:
                            # Sequential alternations (or any expandable inner):
                            # generate cross-product of all expandable branches,
                            # then expand the repeats.
                            seq_lits = _expand_branch_to_literals(inner_repeat, max_results=max_combinations)
                            if seq_lits:
                                expanded = _expand_repeat_combinations(seq_lits, min_c, max_c, max_combinations)
                                if expanded:
                                    groups.append(expanded)
                                    repeat_expanded = True
                if not repeat_expanded:
                    expanded_lits = _expand_branch_to_literals(parsed, max_results=max_combinations)
                    effective_lits = expanded_lits if expanded_lits else branch_lits
                    if has_case_insensitive:
                        all_variants: list[str] = []
                        for lit in effective_lits:
                            all_variants.extend(_expand_case_variants(lit, max_combinations))
                        if all_variants:
                            groups.append(sorted(set(all_variants))[:max_combinations])
                    else:
                        groups.append(effective_lits[:max_combinations])

    # Phase 1b: IN-based alternation repeats (single-char alts optimised
    # to IN nodes by re._parser, wrapped in MAX_REPEAT/MIN_REPEAT).
    # These produce cross-product literal combinations.
    for prefix, in_chars, rep_min, rep_max in _in_alt_repeats:
        expanded = _expand_repeat_combinations(in_chars, rep_min, rep_max, max_combinations)
        if expanded:
            if prefix:
                expanded = [prefix + lit for lit in expanded]
            groups.append(expanded)

    def _make_group_from_branch_combos(combos: list[str], fallback: str, budget: int, groups_out: list) -> None:
        """Build a prefilter group from *combos*, truncating to *budget*.

        When *combos* exceeds *budget*, the group is skipped entirely —
        truncation with a fallback prefix/suffix would inject a literal
        that is a substring of every kept combo, creating suboptimal
        literals within the group.  Phase 1 mandatory groups already
        guarantee prefilter coverage for all matches.
        """
        if not combos or len(combos) > budget:
            return
        trimmed = sorted(set(combos), key=lambda s: (len(s), s))[:budget]
        if trimmed:
            groups_out.append(trimmed)

    # Phase 2: groups from alternation contexts
    for prefix, branch_lits, suffix in _alt_contexts:
        full_combos = [prefix + b + suffix for b in branch_lits]
        if prefix and suffix:
            # Generate partial groups too
            prefix_combos = [prefix + b for b in branch_lits]
            suffix_combos = [b + suffix for b in branch_lits]
            combo_pairs = [(full_combos, prefix + suffix), (prefix_combos, prefix), (suffix_combos, suffix)]
            for combos, fallback in combo_pairs:
                _make_group_from_branch_combos(combos, fallback, max_combinations, groups)
        else:
            mandatory = prefix + suffix
            _make_group_from_branch_combos(full_combos, mandatory, max_combinations, groups)

    # Phase 2: groups from shortened alternation contexts
    for prefix, pure_lits, prefix_lits, suffix_lits, core_lits, suffix in _shortened_alt_contexts:
        # pure_lits: combine with BOTH prefix and suffix
        # prefix_lits: trailing shortened → combine with PREFIX only
        # suffix_lits: leading shortened → combine with SUFFIX only
        # core_lits: both shortened → combine with NEITHER
        if prefix and suffix:
            # Generate partial groups for each category
            if pure_lits:
                full = [prefix + b + suffix for b in pure_lits]
                _make_group_from_branch_combos(full, prefix + suffix, max_combinations, groups)
            if prefix_lits:
                pfx = [prefix + b for b in prefix_lits]
                _make_group_from_branch_combos(pfx, prefix, max_combinations, groups)
            if suffix_lits:
                sfx = [b + suffix for b in suffix_lits]
                _make_group_from_branch_combos(sfx, suffix, max_combinations, groups)
            if core_lits:
                _make_group_from_branch_combos(core_lits, "", max_combinations, groups)
            # Combined group: all categories together
            all_combos: list[str] = []
            for b in pure_lits:
                all_combos.append(prefix + b + suffix)
            for b in prefix_lits:
                all_combos.append(prefix + b)
            for b in suffix_lits:
                all_combos.append(b + suffix)
            for b in core_lits:
                all_combos.append(b)
            _make_group_from_branch_combos(all_combos, prefix + suffix, max_combinations, groups)
        elif prefix:
            # Only prefix, no suffix
            all_combos: list[str] = []
            for b in pure_lits:
                all_combos.append(prefix + b)
            for b in prefix_lits:
                all_combos.append(prefix + b)
            for b in suffix_lits:
                all_combos.append(b)  # attaches to suffix (empty) → just b
            for b in core_lits:
                all_combos.append(b)
            _make_group_from_branch_combos(all_combos, prefix, max_combinations, groups)
        elif suffix:
            # Only suffix, no prefix
            all_combos: list[str] = []
            for b in pure_lits:
                all_combos.append(b + suffix)
            for b in prefix_lits:
                all_combos.append(b)  # attaches to prefix (empty) → just b
            for b in suffix_lits:
                all_combos.append(b + suffix)
            for b in core_lits:
                all_combos.append(b)
            _make_group_from_branch_combos(all_combos, suffix, max_combinations, groups)
        else:
            # Neither prefix nor suffix — just the literals themselves
            all_combos: list[str] = []
            all_combos.extend(pure_lits)
            all_combos.extend(prefix_lits)
            all_combos.extend(suffix_lits)
            all_combos.extend(core_lits)
            if all_combos:
                _make_group_from_branch_combos(all_combos, "", max_combinations, groups)

    # Phase 2: groups from alternation-repeat contexts
    for prefix, branch_lits, suffix, rep_min, rep_max in _alt_repeat_contexts:
        # Min-level full combos: prefix + branch + suffix
        min_full = [prefix + b + suffix for b in branch_lits]
        max_items = len(branch_lits) ** rep_max
        if rep_max > rep_min and max_items <= max_combinations:
            # Max-level fits: include both min-full and max-full
            max_gen = list(branch_lits)
            for _ in range(rep_min, rep_max):
                max_gen = [a + b for a in max_gen for b in branch_lits]
            max_full = [prefix + lit + suffix for lit in max_gen]
            combined = sorted(set(min_full + max_full))
            _make_group_from_branch_combos(combined, prefix + suffix, max_combinations, groups)
        elif rep_max > rep_min:
            # Max-level exceeds budget: use anchor-pairs
            anchors = sorted(set([prefix + b for b in branch_lits] + [b + suffix for b in branch_lits]))
            _make_group_from_branch_combos(anchors, prefix + suffix, max_combinations, groups)
        else:
            # rep_max == rep_min: just min_full (plain alternation, no repeat)
            _make_group_from_branch_combos(min_full, prefix + suffix, max_combinations, groups)

    # Phase 2: groups from optional contexts
    for prefix, opt_lit, suffix in _opt_contexts:
        without_opt = prefix + suffix
        with_opt = prefix + opt_lit + suffix
        combos = sorted(set([without_opt, with_opt]))
        if combos:
            groups.append(combos[:max_combinations])

    # Include lookaround-forced literal groups
    groups.extend(_lookaround_groups)

    # De-duplicate groups
    unique: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for g in groups:
        g_sorted = sorted(g)
        key = tuple(g_sorted)
        if key not in seen:
            seen.add(key)
            unique.append(g_sorted)

    # Prune subsumed groups: if every literal in group G is a substring
    # of at least one literal in another group H, then G is redundant —
    # H is more specific (fewer false positives) and subsumes G.
    _to_remove: set[int] = set()
    for i, g in enumerate(unique):
        if i in _to_remove:
            continue
        for j, h in enumerate(unique):
            if i == j or j in _to_remove:
                continue
            if all(any(s in t for t in h) for s in g):
                _to_remove.add(i)
                break
    if _to_remove:
        unique = [g for i, g in enumerate(unique) if i not in _to_remove]

    # Sort groups deterministically: by first element, then length
    unique.sort(key=lambda g: (g[0] if g else "", len(g)))

    return unique if unique else None
