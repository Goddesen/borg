from itertools import product
from re import _parser


def pattern_extract_prefilter_literals(pattern: str, *, max_combinations: int = 20) -> list[str] | None:
    """
    Extract literals from a regex pattern to be used as a prefilter for
    accelerated multi-pattern matching.

    Returns a list of prefilter strings to be interpreted as plain literals.
    They are constructed such that for any string that would match the given
    regex pattern, at least one of the prefilter strings must also match that
    string. Thus, in combination, the prefilter strings can be used as cheap
    inclusion checks to run before running the full regex. This prefilter check
    can end up matching many more strings than the actual regex would.

    Returns None if no useful prefilter literals could be extracted. This
    covers both unparseable patterns and valid patterns that contain no fixed
    literal characters (e.g. ``r"\\d+"``, ``r"^[a-z]*$"``).

    For any _one_ regex this might not be worth it over just checking the full
    regex immediately, but if many regexes are to be checked against many
    inputs, it can be _very_ beneficial to prefilter them to only run the few
    that could match. The real win in such a situation is limiting the amount
    of calls out of the python interpreter to run regex matching

    **Expansion behaviour**

    The function now handles alternations, repetitions, and character groups by
    enumerating all possible literal combinations (up to *max_combinations*).

    - **Alternation** ``(a|b)``: each branch is fully expanded.  If branches
      produce different sets of literals the alternation is treated as a break
      (prefixes are flushed but not combined across branches).
    - **Repetition** ``(ab){1,3}``: expanded by combining inner options into
      sequences of length ``min..max`` (capped practically at 16 copies).
    - **Character classes** ``[abc]``: treated like a single-char alternation.
    - **Case-insensitive flag** ``(?i)``: case variants are generated for
      alphabetic characters.

    When the limit is reached the function returns whatever valid literals it
    has collected so far — it never fails entirely because one branch exceeded
    the budget while others might still be useful.
    """
    try:
        parsed = _parser.parse(pattern)
    except _parser.error:
        return None

    # Detect top-level case-insensitive flag (?i, (?im, etc.)
    has_case_insensitive = pattern.startswith("(?i")

    literals: set[str] = set()
    count = 0  # total combinations produced across all expansions

    def _limit_ok(n: int = 1) -> bool:
        nonlocal count
        if count + n <= max_combinations:
            count += n
            return True
        return False

    def _add(s: str) -> None:
        """Add a non-empty string to literals if within limit."""
        if s and s not in literals and _limit_ok():
            literals.add(s)

    def _expand_case(base: str) -> set[str]:
        """Generate case-insensitive variants of *base* (up to remaining budget)."""
        alpha_positions = [i for i, c in enumerate(base) if c.isalpha()]
        n = len(alpha_positions)
        results: set[str] = set()
        total = 1 << n  # 2^n
        iterations = min(total, max_combinations - count + 1)
        for mask in range(iterations):
            chars = list(base)
            for j, pos in enumerate(alpha_positions):
                if mask & (1 << j):
                    chars[pos] = chars[pos].upper()
                else:
                    chars[pos] = chars[pos].lower()
            candidate = "".join(chars)
            if candidate not in literals and _limit_ok():
                results.add(candidate)
            if count >= max_combinations:
                break
        return results

    def _expand_in(value: list) -> list[str] | None:
        """Expand a character-class (IN) value into individual characters, or
        return None if the class is too large / contains ranges / categories."""
        chars: list[str] = []
        for elem_op, elem_val in value:
            if elem_op is _parser.LITERAL:
                chars.append(chr(elem_val))
            elif elem_op is _parser.RANGE:
                return None  # range → too many options
            elif elem_op is _parser.NEGATE:
                return None  # negated class → too many options
            else:
                return None  # CATEGORY or unknown → skip
        return chars

    def walk(subpattern, flags: int = 0) -> set[str]:
        nonlocal count
        """Walk *subpattern*, returning the set of all possible literal strings
        that can be formed from it (up to the global combination limit).

        Partial prefixes interrupted by non-literal constructs are flushed to
        the global *literals* set. The return value contains fully-expandable
        buffer contents for parent concatenation.
        """
        buffer: list[str] = [""]  # accumulated prefix(es)

        def _flush() -> None:
            for p in buffer:
                if p:
                    _add(p)

        for opcode, value in subpattern:
            if opcode is _parser.LITERAL:
                ch = chr(value)
                buffer = [p + ch for p in buffer]

            elif opcode is _parser.IN:
                expanded = _expand_in(value)
                if expanded is not None:
                    new_buf: list[str] = []
                    for prefix in buffer:
                        for ch in expanded:
                            candidate = prefix + ch
                            if count < max_combinations:
                                new_buf.append(candidate)
                    buffer = new_buf if new_buf else [""]
                else:
                    _flush()
                    buffer = [""]

            elif opcode in (_parser.ANY, _parser.AT):
                _flush()
                buffer = [""]

            elif opcode is _parser.SUBPATTERN:
                gnum, add_flags, _, inner = value
                inner_flags = flags | add_flags
                branch_results = walk(inner, inner_flags)

                if branch_results:
                    new_buf: list[str] = []
                    for prefix in buffer:
                        for br in branch_results:
                            candidate = prefix + br
                            if candidate and count < max_combinations:
                                new_buf.append(candidate)
                    buffer = new_buf if new_buf else [""]
                else:
                    # Group contributed nothing expandable — flush accumulated
                    # prefix(es) then reset (consistent with every other
                    # non-expandable -> reset path).
                    _flush()
                    buffer = [""]

            elif opcode is _parser.BRANCH:
                # value == (None, [branch, …])
                branches = value[1]

                # Save state — branch walks may flush branch-local content
                # that is only valid for individual branches, not globally.
                saved_literals = set(literals)
                saved_count = count

                # Walk each branch and collect results
                branch_results_list: list[set[str]] = []
                for branch in branches:
                    results = walk(branch, flags)
                    branch_results_list.append(results)

                # Roll back any _flush() commits that happened during branch
                # walks.  Branch-local content is only valid for the specific
                # branch, not across all alternation outcomes.
                literals.clear()
                literals.update(saved_literals)
                count = saved_count

                # Check if all branches produced the same expandable content.
                # If branches differ, we can't safely combine — flush prefixes
                # and treat as a break point.
                non_empty = [r for r in branch_results_list if r]
                if not non_empty:
                    # No expandable content from any branch
                    _flush()
                    buffer = [""]
                elif len(non_empty) < len(branch_results_list):
                    # Some branches have content, some don't — can't guarantee
                    # prefilter coverage. Flush prefixes and reset.
                    _flush()
                    buffer = [""]
                else:
                    # All branches have content — check if they're the same set
                    first = branch_results_list[0]
                    all_same = all(r == first for r in branch_results_list)

                    if all_same:
                        # All branches identical (e.g. common prefix factored out)
                        # Combine with buffer normally
                        new_buf: list[str] = []
                        for prefix in buffer:
                            for br in first:
                                candidate = prefix + br
                                if candidate and count < max_combinations:
                                    new_buf.append(candidate)
                        buffer = new_buf if new_buf else [""]
                    else:
                        # Different branches — return union of branch results for
                        # parent concatenation (not _add() directly — that would
                        # produce spurious literals when nested inside MAX_REPEAT
                        # or SUBPATTERN).
                        _flush()
                        union: set[str] = set()
                        for results in branch_results_list:
                            union |= results
                        buffer = list(union) if union else [""]

            elif opcode in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
                min_c, max_c, inner = value
                if max_c is _parser.MAXREPEAT:
                    max_c = 16  # practical cap for unbounded

                # When min_c == 0, the repetition body is optional.  Any
                # _flush() calls inside walk(inner) commit content that is
                # only guaranteed to be present when the repetition fires
                # (1+ copies).  Save/restore the global state to prevent
                # spurious prefilter leaks — identical pattern to Step 3.
                if min_c == 0:
                    saved_literals = set(literals)
                    saved_count = count

                inner_options = walk(inner, flags)

                if min_c == 0:
                    literals.clear()
                    literals.update(saved_literals)
                    count = saved_count
                if not inner_options:
                    # Inner pattern has no expandable content (e.g. .* or \d+)
                    # Buffer content before the repeat is a valid prefilter on its own
                    _flush()
                    buffer = [""]
                    continue

                opts = sorted(inner_options)
                max_len = min(max_c, 16)

                expanded: list[str] = []
                for length in range(min_c, max_len + 1):
                    n_opts = len(opts)
                    needed = n_opts**length
                    if len(expanded) + needed > max_combinations * 10:
                        break  # cap work budget to avoid combinatorial explosion
                    for combo in product(range(n_opts), repeat=length):
                        s = "".join(opts[i] for i in combo)
                        if s:
                            expanded.append(s)
                # Sort by length then alphabetically for deterministic, shortest-first order
                expanded.sort(key=lambda s: (len(s), s))

                if expanded:
                    # Generate cross-product of buffer × expanded, sorted shortest-first.
                    # This ensures short prefilters (more likely to be valid substrings)
                    # are prioritised when the budget is applied later.
                    candidates: list[str] = []
                    if min_c == 0:
                        # Zero copies is valid — keep original buffer entries
                        # (including '' which represents the empty prefix).
                        # An empty buffer entry is the identity for concatenation
                        # and must survive so later literals like 'b' in (a?b)+
                        # can produce 'b' (zero copies of 'a', one of 'b').
                        candidates.extend(buffer)
                    for prefix in buffer:
                        for ex in expanded:
                            candidate = prefix + ex
                            if candidate:
                                candidates.append(candidate)
                    # When min_c >= 1, every match MUST contain at least one
                    # entry from *expanded* as a substring independently of the
                    # buffer prefix.  Adding them as fallback candidates ensures
                    # that even tight budgets that truncate cross-product entries
                    # still satisfy the prefilter contract.
                    if min_c >= 1:
                        for ex in expanded:
                            if ex not in candidates:
                                candidates.append(ex)
                    candidates.sort(key=lambda s: (len(s), s))
                    new_buf: list[str] = []
                    for c in candidates:
                        if count + len(new_buf) >= max_combinations:
                            break
                        new_buf.append(c)
                    buffer = new_buf if new_buf else [""]
                else:
                    _flush()
                    buffer = [""]

            elif opcode in (_parser.ASSERT, _parser.ASSERT_NOT):
                _flush()
                buffer = [""]

            elif opcode in (_parser.GROUPREF, _parser.GROUPREF_EXISTS):
                _flush()
                buffer = [""]

        return set(buffer) - {""}

    result = walk(parsed, 0)
    for s in result:
        _add(s)

    # Case-insensitive expansion of collected literals
    if has_case_insensitive and literals:
        base_literals = list(literals)
        literals.clear()
        for lit in base_literals:
            variants = _expand_case(lit)
            literals |= variants

    return sorted(literals) if literals else None
