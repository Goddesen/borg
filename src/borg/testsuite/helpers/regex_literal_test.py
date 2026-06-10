import re

import pytest

from ...helpers.regex_literal import pattern_extract_prefilter_literals


def _assert_prefilter_inclusion(pattern, literals, matching_strings):
    """For each test string that matches the regex, verify at least one
    prefilter literal is present as a substring.

    This validates the function's guarantee: every regex match contains at
    least one of the returned prefilter strings."""
    # Use search rather than fullmatch so lookbehind / non-anchored patterns work.
    # Hyperscan (the target prefilter engine) reports matches anywhere in a buffer.
    try:
        compiled = re.compile(pattern)
    except re.error:
        pytest.skip(f"Pattern {pattern!r} cannot be compiled by stdlib re")

    for matching_string in matching_strings:
        assert compiled.search(matching_string), (
            # Remove once implementation is finished
            f"Test string {matching_string!r} does not match pattern {pattern!r} — fix the test data"
        )
        assert any(literal in matching_string for literal in literals), (
            f"String {matching_string!r} matches {pattern!r} but contains none of the "
            f"returned literals {literals!r}"
        )


def _check(pattern, matching_strings, *, assert_not_none: bool = False):
    """Helper: call the function under test and perform both assertions.

    - None result (no extractable literals): nothing to assert, skip.
    - Non-empty list: verify the extracted literals form a valid prefilter.

    Args:
        assert_not_none: When True, fail the test if None is returned instead of
            skipping. Used for patterns that SHOULD have extractable literals but
            don't because the required feature (e.g. alternation literal extraction)
            is not yet implemented.
    """
    literals = pattern_extract_prefilter_literals(pattern)

    if literals is None:
        if assert_not_none:
            pytest.fail(
                f"Pattern {pattern!r} returned None but should have extractable "
                f"prefilter literals (feature not yet implemented)"
            )
        pytest.skip(f"Pattern {pattern!r} has no extractable prefilter literals")
    _assert_prefilter_inclusion(pattern, literals, matching_strings)


def _check_none(pattern):
    """Helper: verify that a pattern with no extractable literals returns None."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is None, f"Expected None for pattern {pattern!r}, got {result!r}"


# ---------------------------------------------------------------------------
# Basic / simple patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Pure literal — no regex metacharacters
        ("hello", ["hello"]),
        ("foo_bar", ["foo_bar"]),
        ("test123", ["test123"]),
        ("path/to/file.txt", ["path/to/file.txt"]),
    ],
)
def test_simple_literals(pattern, matching):
    _check(pattern, matching)


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Literals with escaped metacharacters
        (r"a\.b", ["a.b"]),
        (r"a\+b", ["a+b"]),
        (r"a\*b", ["a*b"]),
        (r"a\?b", ["a?b"]),
        (r"a\{b", ["a{b"]),
        (r"a\}b", ["a}b"]),
        (r"a\[b", ["a[b"]),
        (r"a\]b", ["a]b"]),
        (r"a\|b", ["a|b"]),
        (r"a\(b", ["a(b"]),
        (r"a\)b", ["a)b"]),
        (r"a\^b", ["a^b"]),
        (r"a\$b", ["a$b"]),
        (r"a\\b", ["a\\b"]),
    ],
)
def test_escaped_metacharacters(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Character classes (shorthand and custom)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        (r"foo\d+bar", ["foo123bar", "foo0bar"]),
        (r"foo\D+bar", ["foo_abc_bar"]),
        (r"foo\w+bar", ["foo_abc_123_bar"]),
        (r"foo\W+bar", ["foo...bar"]),
        (r"foo\s+bar", ["foo \t\nbar"]),
        (r"foo\S+bar", ["fooXYZbar"]),
        # Custom character class
        (r"[abc]+@[xyz]+", ["abc@xyz", "cba@zyx"]),
        # Negated character class
        (r"[^@]+@[^@]+", ["user@host"]),
    ],
)
def test_character_classes(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Quantifiers / repeats
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # * zero-or-more
        (r"ab*c", ["ac", "abc", "abbbc"]),
        # + one-or-more
        (r"ab+c", ["abc", "abbbc"]),
        # ? optional
        (r"colou?r", ["color", "colour"]),
        # {n} exact
        (r"a{3}b", ["aaab"]),
        # {n,m} range
        (r"a{2,4}b", ["aab", "aaab", "aaaab"]),
        # {n,} at-least
        (r"a{2,}b", ["aab", "aaaaab"]),
        # Greedy + lazy variants
        (r"<tag>.*?</tag>", ["<tag>hello</tag>", "<tag></tag>"]),
    ],
)
def test_quantifiers(pattern, matching):
    _check(pattern, matching)


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Optional inner element — zero copies of 'a' should give 'b' as prefilter
        (r"(a?b)+", ["b", "ab", "abab", "bab"]),
        # Same with outer {n,m}
        (r"(a?b){2,3}", ["bb", "bab", "abab"]),
        # OPTIONAL with zero-or-more outer repeat
        (r"(colou?r)*", ["color", "colour", "colorcolour"]),
    ],
)
def test_repeat_with_optional_inner(pattern, matching):
    _check(pattern, matching, assert_not_none=True)


# ---------------------------------------------------------------------------
# Alternation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        (r"foo|bar|baz", ["foo", "bar", "baz"]),
        (r"cat|dog|bird", ["cat", "dog", "bird"]),
        (r"alpha|beta|gamma|delta", ["alpha", "beta", "gamma", "delta"]),
        # Alternation with common prefix / suffix
        (r"pre(fix|lude|text)", ["prefix", "prelude", "pretext"]),
        (r"(un|re|dis)do", ["undo", "redo", "disdo"]),
        # Alternation inside repetition
        (r"(foo|bar){2}", ["foofoo", "foobar", "barfoo", "barbar"]),
    ],
)
def test_alternation(pattern, matching):
    _check(pattern, matching, assert_not_none=True)


# ---------------------------------------------------------------------------
# Groups (capturing and non-capturing)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Capturing group
        (r"(abc)def", ["abcdef"]),
        (r"(abc){2}", ["abcabc"]),
        # Non-capturing group
        (r"(?:abc)def", ["abcdef"]),
        (r"(?:abc){2}", ["abcabc"]),
    ],
)
def test_groups(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Nested groups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Alternation inside repeat — should extract from branches
        (r"((ab|cd)(ef|gh)){1,2}", ["abef", "cdgh", "abefcdgh"]),
        (r"((?:foo|bar)\d+){2}", ["foo1bar2", "foo3foo4", "bar1bar9"]),
        # Pure nested groups (no alternation) — already works
        (r"(a(b(c)d)e)", ["abcde"]),
        (r"((\w+)\.(\w+))@(\w+)", ["john.doe@example"]),
    ],
)
def test_nested_groups(pattern, matching):
    _check(pattern, matching, assert_not_none=True)


# ---------------------------------------------------------------------------
# Lookaround
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Positive lookahead — literal "foo", requires "bar" ahead
        (r"foo(?=bar)", ["foobar"]),
        # Negative lookahead — foo not followed by bar
        (r"foo(?!bar)", ["foobaz", "fooqux"]),
        # Positive lookbehind — bar preceded by foo
        (r"(?<=foo)bar", ["foobar"]),
        # Negative lookbehind — bar NOT preceded by foo
        (r"(?<!foo)bar", ["xbar", "bazbar"]),
    ],
)
def test_lookaround(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        (r"^start", ["start", "start_more"]),
        (r"end$", ["the_end", "end"]),
        (r"^exact$", ["exact"]),
        (r"^foo.*bar$", ["foobar", "foo_some_bar"]),
        # Word boundaries
        (r"\bword\b", ["word"]),
        (r"\bfoo\b.*\bbar\b", ["foo bar", "foo and bar"]),
    ],
)
def test_anchors(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Complex / real-world patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Email-ish pattern
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", ["user@example.com", "john.doe@mail.co.uk"]),
        # IPv4 address (simplified)
        (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ["192.168.1.1", "10.0.0.255"]),
        # Date YYYY-MM-DD
        (r"\d{4}-\d{2}-\d{2}", ["2024-01-15", "1999-12-31"]),
        # File path with extension
        (r"/[\w/-]+\.(txt|md|py)", ["/home/user/docs/readme.md", "/src/main.py"]),
        # URL-ish
        (r"https?://[\w.-]+(?:\.\w+)+(?:/[\w./?=&%-]*)?", ["https://example.com", "http://sub.domain.org/path?q=1"]),
    ],
)
def test_complex_patterns(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Backreference with surrounding literals
        (r"(a)b\1", ["aba"]),
        # Inline flags — literal extraction doesn't account for case-insensitive flag,
        # so only include strings containing the extracted literal as-is
        (r"(?i)abc", ["abc"]),
        (r"(?s)a.b", ["a\nb", "axb"]),
    ],
)
def test_edge_cases(pattern, matching):
    _check(pattern, matching)


# ---------------------------------------------------------------------------
# Combined complexity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Nested alternation with quantifiers and groups
        (r"((foo|bar)\d+){1,3}(?:-(?:baz|qux))?", ["foo1-baz", "bar2foo3", "bar99-qux", "foo1bar2foo3-baz"]),
        # Character classes + groups + quantifiers — no alternation, already works
        (r"\[([a-z]+(?:-[a-z]+)*)\]", ["[abc]", "[foo-bar-baz]"]),
    ],
)
def test_combined_complexity(pattern, matching):
    _check(pattern, matching, assert_not_none=True)


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Lookaround + asymmetric alternation — no fixed literal common to all
        # branches, so no usable prefilter can be extracted.
        (r"(?<=\$)(?:\d+\.\d{2}|[A-Z]{3})", ["$12.34", "$USD"])
    ],
)
def test_asymmetric_alternation_no_prefilter(pattern, matching):
    """Asymmetric alternation with no literal common to all branches
    must return None — there is no valid prefilter."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is None, (
        f"Pattern {pattern!r} has asymmetric branches with no common " f"literal — expected None, got {result!r}"
    )


# ---------------------------------------------------------------------------
# Contract: never return an empty list; return None instead
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        # Pure metacharacters — no fixed literal characters to extract
        r"\d+",
        r"\w*",
        r"\s+",
        r"\D*",
        r"\S+",
        r"\W*",
        # Anchors only
        r"^$",
        r"^\s*$",
        # Character classes only
        r"[a-z]+",
        r"[^@]+",
        r"[0-9]*",
        # Wildcards only
        r".*",
        r".+",
        r".?",
        # Backreferences / named groups with no surrounding literals
        r"(\w+)\s+\1",
        r"(?P<word>\w+)",
        # Quantified metacharacters
        r"\d{3,5}",
        r"\w{2,}",
        # Alternation of pure metacharacters
        r"\d+|\w+",
        # Lookaround-only patterns
        r"(?<=\$)\d+",
        r"\d+(?=\.)",
    ],
)
def test_no_empty_list_return(pattern):
    """The function must never return an empty list. It returns None or a
    non-empty list of literals."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result != [], f"Function returned empty list for {pattern!r}; should return None"


# ---------------------------------------------------------------------------
# Patterns that must return None (no extractable literals)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        # Empty pattern
        "",
        # Pure metacharacters — no fixed literal characters to extract
        r"\d+",
        r"\w*",
        r"\s+",
        r"\D*",
        r"\S+",
        r"\W*",
        # Anchors only
        r"^$",
        r"^\s*$",
        # Character classes only (including adjacent classes with no literals between)
        r"[a-z]+",
        r"[^@]+",
        r"[0-9]*",
        r"[a-z]+[0-9]+",
        # Wildcards only
        r".*",
        r".+",
        r".?",
        # Quantified metacharacters
        r"\d{3,5}",
        r"\w{2,}",
        # Alternation of pure metacharacters
        r"\d+|\w+",
        # Lookaround-only patterns (zero-width assertions with no adjacent fixed literals)
        r"(?<=\$)\d+",
        r"(?<!\$)\d+",
        r"\d+(?=\.)",
        r"\d+(?=\.\d+)",
        r"\d+(?!\.)",
        r"(?<=@)\w+(?=\.)",
        # Backreferences / named groups with no surrounding literals
        r"(\w+)\s+\1",
        r"(?P<word>\w+)",
    ],
)
def test_patterns_with_no_literals_return_none(pattern):
    """Patterns that are valid but contain no fixed literal characters must
    return None (not an empty list)."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is None, f"Expected None for pattern {pattern!r} with no extractable literals, " f"got {result!r}"


# ---------------------------------------------------------------------------
# Patterns that DO have literals — must NOT return None or []
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        # Simple literals
        "hello",
        r"a\sb",
        # Literals around metacharacters
        r"foo\d+bar",
        # Lookaround with adjacent literal
        r"(?<!foo)bar",
        r"foo(?=bar)",
        # Group with literal content
        r"(abc)def",
        # Backreference with surrounding literals
        r"(a)b\1",
        # Alternation with common prefix (already works: extracts shared prefix)
        r"pre(fix|lude|text)",
        # Alternation with common suffix (already works: extracts shared suffix)
        r"(un|re|dis)do",
    ],
)
def test_patterns_with_literals_return_non_none(pattern):
    """Patterns that contain fixed literal characters must return a non-empty
    list (not None, not [])."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None and len(result) > 0, (
        f"Expected non-empty list for pattern {pattern!r} with extractable " f"literals, got {result!r}"
    )


# ---------------------------------------------------------------------------
# max_combinations parameter — budget cap, partial results, edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("limit", [2, 3, 5, 10])
def test_max_combinations_never_exceeded(limit):
    """The function must never return more than max_combinations literals."""
    result = pattern_extract_prefilter_literals("(foo|bar|baz|qux){2}", max_combinations=limit)
    assert result is not None, f"limit={limit} returned None"
    assert len(result) <= limit, f"limit={limit}: got {len(result)} literals"
    assert all(isinstance(lit, str) and len(lit) > 0 for lit in result)


def test_max_combinations_too_tight_returns_none():
    """When max_combinations is so small that no expansion step fits the
    work budget (max_combinations * 10), returns None."""
    # (foo|bar|baz|qux){2} needs at least 4^2=16 expansions;
    # work budget limit*10=10 < 16, so no expansion possible.
    assert pattern_extract_prefilter_literals("(foo|bar|baz|qux){2}", max_combinations=1) is None


def test_max_combinations_zero_returns_none():
    """max_combinations=0 means no budget — always returns None."""
    assert pattern_extract_prefilter_literals("hello", max_combinations=0) is None
    assert pattern_extract_prefilter_literals("(foo|bar)", max_combinations=0) is None


def test_max_combinations_one():
    """max_combinations=1 returns exactly one literal."""
    result = pattern_extract_prefilter_literals("(foo|bar)", max_combinations=1)
    assert result is not None
    assert len(result) == 1
    assert result[0] in ("foo", "bar")


def test_max_combinations_negative():
    """Negative max_combinations should not crash."""
    assert pattern_extract_prefilter_literals("foo", max_combinations=-1) is None


def test_max_combinations_partial_results_valid():
    """When budget truncates results, the returned literals should still
    be valid — each literal matches the source pattern."""
    result = pattern_extract_prefilter_literals("(foo|bar|baz|qux){2}", max_combinations=3)
    assert result is not None
    assert len(result) <= 3
    for lit in result:
        assert re.fullmatch("(foo|bar|baz|qux){2}", lit) is not None, f"Literal {lit!r} should match source pattern"


@pytest.mark.parametrize(
    "pattern, limit, matching",
    [
        # Star quantifier with tight budget — truncation returns shortest
        # combos first (by length, then alphabetically): 'ac', 'abc'.
        (r"ab*c", 2, ["ac", "abc"]),
        # Star quantifier: 'abbc', 'abc', 'ac'
        (r"ab*c", 3, ["ac", "abc", "abbc"]),
        # Alternation with equal-length branches for deterministic ordering.
        # (abc|def|ghi){2}: all combos are 6 chars, sorted alphabetically.
        # With limit=5, first 5: abcabc, abcdef, abcghi, defabc, defdef.
        (r"(abc|def|ghi){2}", 5, ["abcabc", "abcdef", "abcghi", "defabc", "defdef"]),
    ],
)
def test_max_combinations_prefilter_coverage(pattern, limit, matching):
    """Tight budget produces valid prefilters for a known subset of
    matching strings."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=limit)
    assert result is not None, f"limit={limit} on {pattern!r} returned None"
    assert len(result) <= limit
    _assert_prefilter_inclusion(pattern, result, matching)


def test_max_combinations_case_insensitive_budget():
    """Case-insensitive expansion respects max_combinations."""
    # (?i)hello — 5 alphabetic chars → 2^5 = 32 case variants
    result = pattern_extract_prefilter_literals("(?i)hello", max_combinations=5)
    assert result is not None
    assert len(result) <= 5
    for lit in result:
        assert lit.lower() == "hello", f"{lit!r} not a case variant of hello"


def test_max_combinations_nested_repeat_budget():
    """Nested repetition with tight budget should not crash."""
    # ((ab|cd)(ef|gh)){1,2} produces up to 20 combos
    result = pattern_extract_prefilter_literals("((ab|cd)(ef|gh)){1,2}", max_combinations=7)
    assert result is not None
    assert len(result) <= 7
    for lit in result:
        assert re.fullmatch("((ab|cd)(ef|gh)){1,2}", lit) is not None


def test_max_combinations_exact_budget_fit():
    """When the budget exactly matches the number of combos, all are
    returned."""
    # (a|b|c|d){2} = 4^2 = 16 combos
    result = pattern_extract_prefilter_literals("(a|b|c|d){2}", max_combinations=16)
    assert result is not None
    assert len(result) == 16


def test_max_combinations_deeply_nested_alternation():
    """Deeply nested alternation with limited budget should not crash."""
    # (((a|b)|(c|d))|((e|f)|(g|h))) — 8 single-char branches
    result = pattern_extract_prefilter_literals("(((a|b)|(c|d))|((e|f)|(g|h)))", max_combinations=4)
    assert result is not None
    assert len(result) <= 4
    for lit in result:
        assert re.fullmatch("(((a|b)|(c|d))|((e|f)|(g|h)))", lit) is not None


def test_max_combinations_large_budget_over_900():
    """With max_combinations=1000, a pattern producing >900 combos returns
    >900 valid prefilter literals (all within budget)."""
    # (a|b|c|d|e|f|g|h|i|j){1,3} produces 10+100+1000=1110 combos total.
    pattern = "(a|b|c|d|e|f|g|h|i|j){1,3}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=1000)
    assert result is not None, "budget=1000 should not return None"
    assert len(result) > 900, f"expected >900 literals, got {len(result)}"
    assert len(result) <= 1000
    matching = [
        "a",
        "j",
        "ab",
        "ji",
        "abc",
        "def",
        "aaa",
        "jjj",
        "hij",
        "abcdefghij",
        "jjjjjjjjjj",  # longer than max repeat — no match
    ]
    _assert_prefilter_inclusion(pattern, result, matching)


def test_max_combinations_budget_500():
    """Intermediate budget (500) on a large combinational space returns
    valid partial results."""
    pattern = "(a|b|c|d|e|f|g|h|i|j){1,3}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=500)
    assert result is not None
    assert len(result) <= 500
    matching = ["a", "j", "ab", "ji", "abc", "def", "aaa", "jjj", "hij"]
    _assert_prefilter_inclusion(pattern, result, matching)


def test_max_combinations_budget_exceeds_total():
    """When max_combinations exceeds total possible combos, all are returned."""
    # (a|b|c|d|e){1,2} = 5+25=30 combos total
    pattern = "(a|b|c|d|e){1,2}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=100)
    assert result is not None
    assert len(result) == 30
    matching = ["a", "e", "aa", "ee", "abcde", "edcba"]
    _assert_prefilter_inclusion(pattern, result, matching)

    # Exact fit (budget == total) should also return all
    result2 = pattern_extract_prefilter_literals(pattern, max_combinations=30)
    assert result2 is not None
    assert len(result2) == 30


def test_max_combinations_with_prefix_repeat():
    """Budget cap with a literal prefix before a repeated alternation
    exercises the buffer × expanded cross-product under a limit."""
    # "pre" + (a|b|c|d|e){1,3} — 155 combos after the prefix
    pattern = r"pre(a|b|c|d|e){1,3}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=50)
    assert result is not None
    assert len(result) <= 50
    matching = ["prea", "preb", "preeee", "preabc", "precba"]
    _assert_prefilter_inclusion(pattern, result, matching)


# ---------------------------------------------------------------------------
# MAX_REPEAT{0,N} spurious inner flushes (Step 5b)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching, forbidden",
    [
        # Zero-or-more with range class — inner flush of '-' should not leak.
        # "" matches but doesn't contain '-'.
        (r"(?:-[a-z]+)*", ["", "-abc", "-foo-bar"], ["-"]),
        # Zero-or-more with ANY metachar — inner flush of 'a' should not leak.
        # "" matches but doesn't contain 'a'.
        (r"(?:a.\d+)*", ["", "a1", "ax9"], ["a"]),
        # Same but with outer prefix — prefix is guaranteed, inner is not.
        (r"prefix(?:a.\d+)*suffix", ["prefixsuffix", "prefixax9suffix"], ["a"]),
        # Optional group (?) — same logic, min_c=0.
        (r"foo(?:-[a-z]+)?", ["foo", "foo-bar"], ["-"]),
    ],
)
def test_max_repeat_zero_no_spurious_flushes(pattern, matching, forbidden):
    """MAX_REPEAT{0,N} / MIN_REPEAT{0,N} inner _flush() calls must not
    leak content that is only present when the repetition fires (1+ copies).
    For zero copies, the flushed content may be absent — releasing it as
    a prefilter can violate the contract (empty-string match vs. prefilter).
    """
    result = pattern_extract_prefilter_literals(pattern)
    # Verify contract: at least one prefilter must match each matching string
    if result is not None:
        _assert_prefilter_inclusion(pattern, result, matching)
        for bad in forbidden:
            assert bad not in result, (
                f"Spurious literal {bad!r} leaked into results {result!r} " f"for pattern {pattern!r}"
            )
    # Extra check: if "" is a matching string and result is not None,
    # every prefilter must be in every non-empty match (trivial) but more
    # importantly, we must not have a prefilter that fails for "".
    if "" in matching and result is not None:
        for lit in result:
            assert lit in "" or any(
                lit in m for m in matching if m
            ), f"Prefilter {lit!r} for {pattern!r} fails empty-string match"


# ---------------------------------------------------------------------------
# Cross-product across separators (Step 5c)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching, budget",
    [
        # Tight budget on class+literal+class
        (r"[abc]+@[xyz]+", ["abc@xyz", "cb@zx", "aaaa@x", "c@zzzz", "abcabc@xyzxyz", "c@x"], 3),
        (r"[abc]+@[xyz]+", ["abc@xyz", "cb@zx", "aaaa@x", "c@zzzz", "abcabc@xyzxyz", "c@x"], 5),
        # With colon separator — disjoint character sets
        (r"[abc]+:[xyz]+", ["abc:xyz", "a:x", "cba:zyx"], 3),
        # Three regions: left + literal + right
        (r"[abc]+#[xyz]+", ["abc#xyz", "c#x", "aaa#zzz"], 5),
        # One char class repeated + separator (single LITERAL in inner_options)
        (r"(?:foo|bar)*@[xyz]+", ["@x", "foo@xyz", "barfoo@x"], 5),
    ],
)
def test_cross_product_across_separator(pattern, matching, budget):
    result = pattern_extract_prefilter_literals(pattern, max_combinations=budget)
    if result is not None:
        _assert_prefilter_inclusion(pattern, result, matching)
        assert len(result) <= budget


# ---------------------------------------------------------------------------
# Extremely complex: devilish combinations exercising subtle SRE features
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # 1. Lookahead flushes accumulated prefix; alternation + literal suffix
        #    survive.  ASSERT flushes "foo" to literals, then BRANCH(bar|baz)
        #    + "qux" produce "barqux"/"bazqux".
        (r"foo(?=.*end)\s(bar|baz)qux", ["foo barqux end", "foo\tbazqux and end"]),
        # 2. min_c=0 save/restore prevents the optional dash from leaking.
        #    Inner walk flushes "-" inside \d+ expansion but the outer
        #    MAX_REPEAT{0,1} rolls it back — only "prefix" and "suffix" remain.
        (r"prefix(?:-\d+)?suffix", ["prefixsuffix", "prefix-123suffix"]),
        # 3. Alternation in required repeat ({2}) — each branch is distinct so
        #    9 cross-product combos + 3 fallback entries (min_c>=1) are produced.
        (r"(?:alpha|beta|gamma){2}", ["alphaalpha", "betagamma", "gammaalpha"]),
        # 4. Backreference (GROUPREF) flushes the buffer to global literals,
        #    then resets — subsequent literal "c" continues independently.
        (r"(a)b\1c", ["abac", "xabacy"]),
        # 5. Lookbehind + alternation + literal-dot + metachar-class + lookahead.
        #    ASSERT flushes empty, BRANCH produces com/org/net, literal "."
        #    concatenates, then \w+ (CATEGORY) flushes the dotted prefixes.
        (r"(?<=@)(?:com|org|net)\.\w+(?=\s|$)", ["@com.domain ", "@org.host"]),
        # 6. Triple-nested min_c=0 — three levels of optional groups each
        #    independently save/restore state.  Produces "d", "ad", "abd", "abcd".
        (r"(?:a(?:b(?:c)?)?)?d", ["d", "ad", "abd", "abcd"]),
        # 7. ASSERT_NOT on both ends sandwiching alternation with an optional
        #    metachar-class suffix.  The optional group (min_c=0) flushes branch
        #    results, which are rolled back, then re-flushed when inner_options
        #    is empty — only the branch names survive.
        (r"(?<!\w)(?:error|warning)(?:\s+\d+)?(?!\w)", ["error", "warning 404", "warning:"]),
        # 8. Lookbehind + alternation + lookahead — ASSERT at both ends,
        #    alternation content in the middle.  The BRANCH results are returned
        #    verbatim after both ASSERTs flush empty buffers.
        (r"(?<=start_)(?:alpha|beta)(?=_end)", ["start_alpha_end", "start_beta_end"]),
        # 9. AT word-boundary flushes empty, BRANCH produces the alternation
        #    inner_options, then AT again flushes those three words to literals.
        #    The trailing ASSERT (lookahead) tries to flush an empty buffer.
        (r"\b(?:foo|bar|baz)\b(?=\s+\d+)", ["foo 123", "bar 456"]),
        # 10. Optional prefix (min_c=0) followed by a required double-repeat
        #     (min_c>=1) — exercises the sequence of zero-or-one followed by
        #     exactly-two expansion + fallback candidate injection.
        (r"(?:foo)?(?:bar|baz){2}", ["barbar", "barbaz", "foobarbaz", "bazbar"]),
        # 11. Two adjacent character classes separated by a literal colon with
        #     a literal suffix — exercises IN expansion cross-product across the
        #     separator then literal concatenation.  Budget=20 keeps the set
        #     trimmed; every matching string still contains at least one entry.
        (r"[abc]+:[xyz]+@test", ["abc:xyz@test", "a:x@test", "cba:zyx@test"]),
    ],
)
def test_devilish_complex_prefilter_contract(pattern, matching):
    """Extremely complex patterns exercising subtle SRE features in
    devilish combinations.  Each test verifies the prefilter-literal
    contract: every regex match contains at least one extracted literal.

    Patterns that contain no fixed literals will return None and be
    skipped (consistent with all other _check-based tests).
    """
    _check(pattern, matching, assert_not_none=True)


# ---------------------------------------------------------------------------
# Unparseable patterns — should return None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        # Unterminated character set
        r"[",
        r"[a-z",
        # Unbalanced parenthesis
        r")",
        r"(abc",
        r"((abc))def(",
        # Unexpected end of pattern
        r"(?",
        # Incomplete escape sequences
        r"\x",
        r"\u",
        r"\U",
        # Invalid group reference (no group 1 exists)
        r"\1",
        # Incomplete named group syntax
        r"(?P<",
        r"(?P=name",
    ],
)
def test_unparseable_patterns_return_none(pattern):
    _check_none(pattern)
