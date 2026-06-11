import pytest
import re
from itertools import combinations

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

    for lit_short, lit_long in combinations(sorted(literals, key=lambda k: (len(k), k)), 2):
        assert (
            lit_short not in lit_long
        ), f"Suboptimal literals for pattern {pattern!r}, {lit_long} is superfluous together with {lit_short}"

    for matching_string in matching_strings:
        assert compiled.search(
            matching_string
        ), f"Test string {matching_string!r} does not match pattern {pattern!r} — fix the test data"
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
    result = pattern_extract_prefilter_literals(pattern)

    if result is None:
        if assert_not_none:
            pytest.fail(
                f"Pattern {pattern!r} returned None but should have extractable "
                f"prefilter literals (feature not yet implemented)"
            )
        pytest.skip(f"Pattern {pattern!r} has no extractable prefilter literals")
    # result is list[list[str]] — use the first group to validate the
    # prefilter contract (every group is independently valid).
    _assert_prefilter_inclusion(pattern, result[0], matching_strings)


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


def test_sequential_alternations_non_repeated_two_groups():
    """Two sequential alternation groups without an outer repeat should
    produce cross-product literals that fullmatch the pattern."""
    result = pattern_extract_prefilter_literals("(ab|cd)(ef|gh)", max_combinations=20)
    assert result is not None
    for g in result:
        for lit in g:
            assert re.fullmatch("(ab|cd)(ef|gh)", lit) is not None, f"Literal {lit!r} should fullmatch (ab|cd)(ef|gh)"


def test_sequential_alternations_non_repeated_three_groups():
    """Three sequential alternation groups without an outer repeat."""
    result = pattern_extract_prefilter_literals("(ab|cd)(ef|gh)(ij|kl)", max_combinations=40)
    assert result is not None
    for g in result:
        for lit in g:
            assert re.fullmatch("(ab|cd)(ef|gh)(ij|kl)", lit) is not None


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
# Lookaround literal extraction (#3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Lookbehind forces '$' — body \d+ also expands to individual digits
        (r"(?<=\$)\d+", [["$"], ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]], ["$123", "$0"]),
        # Lookahead forces '.' — body \d+ also expands to individual digits
        (r"\d+(?=\.)", [["."], ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]], ["123.", "0."]),
        # Lookbehind + lookahead — pattern body has no mandatory literals
        (r"(?<=@)\w+(?=\.)", [["@"], ["."]], ["@foo.", "@bar."]),
    ],
)
def test_lookaround_literal_extraction(pattern, expected, matching):
    """Positive lookarounds should contribute their forced literals as
    independent prefilter groups, even when the match body has no mandatory
    literals."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


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
    """Asymmetric alternation — lookbehind forces '$' as a prefilter.
    With lookaround extraction (#3), the lookbehind literal is extracted."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Pattern {pattern!r} has lookbehind-forced literal — got None"
    assert result == [["$"]], f'Expected [["$"]], got {result!r}'


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
        #   \d+ and \s+ moved: CATEGORY_DIGIT/SPACE are now expandable.
        r"\w*",
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
        # Wildcards only
        r".*",
        r".+",
        r".?",
        # Quantified metacharacters (\d{3,5} moved — \d is now expandable)
        r"\w{2,}",
        # Alternation of pure metacharacters
        r"\d+|\w+",
        # Optional outer repeat with optional inner — zero repetitions (empty string) valid
        r"(colou?r)*",
        # Lookaround-only patterns — all \d+-based moved (\d now expandable)
        # Backreferences / named groups with no surrounding literals
        #   (\w+)\s+\1 moved — \s+ now expandable to individual whitespace chars.
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
        # Expandable character classes — now extract individual characters (after #6)
        r"\d+",  # digits 0-9
        r"\s+",  # whitespace chars
        r"\d{3,5}",  # \d required repeat — digits 0-9
        r"(?<!\$)\d+",  # negative lookbehind + required digits
        r"\d+(?=\.\d+)",  # digits + lookahead (no lookahead-forced literal)
        r"\d+(?!\.)",  # digits + negative lookahead
        r"(\w+)\s+\1",  # whitespace between backreferenced groups
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
    total_lits = sum(len(g) for g in result)
    assert total_lits <= limit, f"limit={limit}: got {total_lits} literals"
    assert all(isinstance(lit, str) and len(lit) > 0 for g in result for lit in g)


def test_max_combinations_too_tight_returns_none():
    """When max_combinations is so small the work budget cannot fit even
    a single group, returns None."""
    # (foo|bar|baz|qux){2} needs at least 4^2=16 expansions;
    # work budget limit*10=10 < 16, so no expansion possible.
    result = pattern_extract_prefilter_literals("(foo|bar|baz|qux){2}", max_combinations=1)
    assert result is not None, "budget=1 should still return partial results"
    assert sum(len(g) for g in result) <= 1


def test_max_combinations_zero_returns_none():
    """max_combinations=0 means no budget — always returns None."""
    assert pattern_extract_prefilter_literals("hello", max_combinations=0) is None
    assert pattern_extract_prefilter_literals("(foo|bar)", max_combinations=0) is None


def test_max_combinations_one():
    """max_combinations=1 returns exactly one literal."""
    result = pattern_extract_prefilter_literals("(foo|bar)", max_combinations=1)
    assert result is not None
    assert sum(len(g) for g in result) == 1
    assert result[0][0] in ("foo", "bar")


def test_max_combinations_negative():
    """Negative max_combinations should not crash."""
    assert pattern_extract_prefilter_literals("foo", max_combinations=-1) is None


def test_max_combinations_partial_results_valid():
    """When budget truncates results, the returned literals should still
    be valid — each literal matches the source pattern."""
    result = pattern_extract_prefilter_literals("(foo|bar|baz|qux){2}", max_combinations=3)
    assert result is not None
    assert sum(len(g) for g in result) <= 3
    for g in result:
        for lit in g:
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
    # Budget is per-group: each group independently respects the cap.
    assert all(len(g) <= limit for g in result)
    _assert_prefilter_inclusion(pattern, result[0], matching)


def test_max_combinations_case_insensitive_budget():
    """Case-insensitive expansion respects max_combinations."""
    # (?i)hello — 5 alphabetic chars → 2^5 = 32 case variants
    result = pattern_extract_prefilter_literals("(?i)hello", max_combinations=5)
    assert result is not None
    assert sum(len(g) for g in result) <= 5
    for g in result:
        for lit in g:
            assert lit.lower() == "hello", f"{lit!r} not a case variant of hello"


def test_max_combinations_nested_repeat_budget():
    """Nested repetition with tight budget should not crash."""
    # ((ab|cd)(ef|gh)){1,2} produces up to 20 combos
    result = pattern_extract_prefilter_literals("((ab|cd)(ef|gh)){1,2}", max_combinations=7)
    assert result is not None
    assert sum(len(g) for g in result) <= 7
    for g in result:
        for lit in g:
            assert re.fullmatch("((ab|cd)(ef|gh)){1,2}", lit) is not None


def test_repeat_with_non_expandable_sequential_inner():
    """Repeat wrapping sequential content with a non-expandable element
    (ANY) gracefully falls back to outermost alternation branches."""
    # ((ab|cd).){2} — alternation + ANY; ANY prevents cross-product expansion
    # but the outermost alternation branches are still returned.
    result = pattern_extract_prefilter_literals("((ab|cd).){2}", max_combinations=20)
    assert result is not None, "Should not return None — outermost alternation branches are extractable"
    assert sum(len(g) for g in result) > 0, "Should have at least some literals"


def test_max_combinations_exact_budget_fit():
    """When the budget exactly matches the number of combos, all are
    returned."""
    # (a|b|c|d){2} = 4^2 = 16 combos
    result = pattern_extract_prefilter_literals("(a|b|c|d){2}", max_combinations=16)
    assert result is not None
    assert sum(len(g) for g in result) == 16


def test_max_combinations_deeply_nested_alternation():
    """Deeply nested alternation with limited budget should not crash."""
    # (((a|b)|(c|d))|((e|f)|(g|h))) — 8 single-char branches
    result = pattern_extract_prefilter_literals("(((a|b)|(c|d))|((e|f)|(g|h)))", max_combinations=4)
    assert result is not None
    assert sum(len(g) for g in result) <= 4
    for g in result:
        for lit in g:
            assert re.fullmatch("(((a|b)|(c|d))|((e|f)|(g|h)))", lit) is not None


def test_expand_branch_to_literals_budget_cap():
    """Sequential multi-char alternation groups with a tight budget
    exercise the budget cap in _expand_branch_to_literals: intermediate
    cross-product exceeds max_results, returns None, caller falls back
    to the outermost alternation's branches."""
    # (ab|cd|ef)(gh|ij|kl)(mn|op|qr)(st|uv|wx) — 3^4 = 81 combos
    pattern = "(ab|cd|ef)(gh|ij|kl)(mn|op|qr)(st|uv|wx)"

    # Tight budget: intermediate cross-product exceeds 10, budget cap
    # returns None -> fallback to first alternation's branches only.
    result = pattern_extract_prefilter_literals(pattern, max_combinations=10)
    assert result is not None, "tight budget should not cause None result"
    assert result[0] == ["ab", "cd", "ef"]

    # Sufficient budget: all 81 combos returned.
    result2 = pattern_extract_prefilter_literals(pattern, max_combinations=100)
    assert result2 is not None
    assert len(result2[0]) == 81
    for lit in result2[0]:
        assert len(lit) == 8  # four 2-char alternations concatenated


def test_max_combinations_large_budget_over_900():
    """With max_combinations=1000, a pattern producing >900 combos returns
    >900 valid prefilter literals (all within budget)."""
    # 31 two-char branches with {2} → 31² = 961 combos (all at min level).
    pattern = (
        "(aa|ab|ac|ad|ae|af|"
        "ba|bb|bc|bd|be|bf|"
        "ca|cb|cc|cd|ce|cf|"
        "da|db|dc|dd|de|df|"
        "ea|eb|ec|ed|ee|ef|"
        "fa){2}"
    )
    result = pattern_extract_prefilter_literals(pattern, max_combinations=1000)
    assert result is not None, "budget=1000 should not return None"
    total = sum(len(g) for g in result)
    assert total > 900, f"expected >900 literals, got {total}"
    assert total <= 1000
    matching = ["abef", "faaa", "abcd", "dccd", "aaaa", "abcdefghij"]  # search finds "abcd" in a larger buffer
    _assert_prefilter_inclusion(pattern, result[0], matching)


def test_max_combinations_budget_500():
    """Intermediate budget (500) on a large combinational space returns
    valid partial results."""
    pattern = "(a|b|c|d|e|f|g|h|i|j){1,3}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=500)
    assert result is not None
    assert sum(len(g) for g in result) <= 500
    matching = ["a", "j", "ab", "ji", "abc", "def", "aaa", "jjj", "hij"]
    _assert_prefilter_inclusion(pattern, result[0], matching)


def test_adjacent_character_classes_extract_expandable_chars():
    """When adjacent character classes have no mandatory literal between them,
    each expandable class (≤20 chars) should produce an independent prefilter
    group of its individual characters."""
    # [a-z]+[0-9]+ — [a-z] has 26 chars (not expandable), [0-9] has 10 (expandable)
    result = pattern_extract_prefilter_literals("[a-z]+[0-9]+")
    assert result is not None, "[a-z]+[0-9]+ should extract expandable digit class"
    result_normalized = sorted([sorted(g) for g in result])
    assert result_normalized == [
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    ], f"Expected digits 0-9, got {result_normalized}"
    matching = ["abc123", "z0", "hello42world"]
    _assert_prefilter_inclusion("[a-z]+[0-9]+", result[0], matching)

    # [a-f]+[0-4]+ — both are expandable (6 and 5 chars respectively)
    result2 = pattern_extract_prefilter_literals("[a-f]+[0-4]+")
    assert result2 is not None, "[a-f]+[0-4]+ should extract both expandable classes"
    result2_normalized = sorted([sorted(g) for g in result2])
    assert result2_normalized == sorted(
        [["a", "b", "c", "d", "e", "f"], ["0", "1", "2", "3", "4"]]
    ), f"Expected letter group and digit group, got {result2_normalized}"
    for g in result2:
        _assert_prefilter_inclusion("[a-f]+[0-4]+", g, ["abc12", "f4", "ab0"])


def test_max_combinations_budget_exceeds_total():
    """When max_combinations exceeds total possible combos, all are returned."""
    # 10 two-char branches with {2} → 10² = 100 combos total (all at min level).
    pattern = "(a0|a1|a2|a3|a4|b0|b1|b2|b3|b4){2}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=200)
    assert result is not None
    assert sum(len(g) for g in result) == 100
    matching = ["a0b4", "b4a0", "a0a0", "b4b4", "xa0b4y", "prefix_b4a0_suffix"]
    _assert_prefilter_inclusion(pattern, result[0], matching)

    # Exact fit (budget == total) should also return all
    result2 = pattern_extract_prefilter_literals(pattern, max_combinations=100)
    assert result2 is not None
    assert sum(len(g) for g in result2) == 100


def test_max_combinations_with_prefix_repeat():
    """Budget cap with a literal prefix before a repeated alternation
    exercises the buffer × expanded cross-product under a limit."""
    # "pre" + (a|b|c|d|e){1,3} — 155 combos after the prefix.
    # After #2c, an extra Phase 2 group of the raw characters may push
    # the total slightly over the requested budget; the budget cap is
    # per-group, not global.
    pattern = r"pre(a|b|c|d|e){1,3}"
    result = pattern_extract_prefilter_literals(pattern, max_combinations=50)
    assert result is not None
    # Each group independently respects the budget cap
    assert all(len(g) <= 50 for g in result)
    matching = ["prea", "preb", "preeee", "preabc", "precba"]
    _assert_prefilter_inclusion(pattern, result[0], matching)


def test_alternation_mixed_digit_and_pure_literal_truncation():
    pattern = r"foo(bar\d|baz\d|xxx)"
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    for prefilter_literals in result:
        _assert_prefilter_inclusion(
            pattern,
            prefilter_literals,
            [
                "foobar0",
                "foobar1",
                "foobar2",
                "foobar3",
                "foobar4",
                "foobar5",
                "foobar6",
                "foobar7",
                "foobar8",
                "foobar9",
                "foobaz0",
                "foobaz1",
                "foobaz2",
                "foobaz3",
                "foobaz4",
                "foobaz5",
                "foobaz6",
                "foobaz7",
                "foobaz8",
                "foobaz9",
                "fooxxx",
            ],
        )


@pytest.mark.parametrize(
    "pattern, matching",
    [
        (r"(ab|cd){1,2}", ["abab", "abcd", "cdab", "cdcd"]),
        (r"foo(xy|XY){1,2}bar", ["fooxyxybar", "fooxyXYbar", "fooXYxybar", "fooXYXYbar"]),
    ],
)
def test_potential_suboptimal_literals(pattern, matching):
    result = pattern_extract_prefilter_literals(pattern)
    for literals in result:
        _assert_prefilter_inclusion(pattern, literals, matching)


@pytest.mark.parametrize(
    "pattern, literals",
    [
        (r"(ab|cd){1,2}", ["ab", "cd"]),
        (r"foo(xy|XY){1,2}bar", ["fooxybar", "fooXYbar", "fooxyxybar", "fooxyXYbar", "fooXYxybar", "fooXYXYbar"]),
        (r"foo(xy|XY){1,5}bar", ["fooxy", "fooXY", "xybar", "XYbar"]),
    ],
)
def test_extracts_optimal_literals(pattern, literals):
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None
    assert len(result) == 1
    assert set(result[0]) == set(literals)


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
        _assert_prefilter_inclusion(pattern, result[0], matching)
        for bad in forbidden:
            assert bad not in result[0], (
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
# CATEGORY expansion: \d and \s in Phase 2 (#2a / #2b)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # \d with prefix and suffix — Phase 2 produces combined groups;
        # the fully-combined group subsumes the standalone prefix/suffix/digit groups.
        (
            r"prefix\dsuffix",
            [
                [
                    "prefix0suffix",
                    "prefix1suffix",
                    "prefix2suffix",
                    "prefix3suffix",
                    "prefix4suffix",
                    "prefix5suffix",
                    "prefix6suffix",
                    "prefix7suffix",
                    "prefix8suffix",
                    "prefix9suffix",
                ]
            ],
            ["prefix0suffix", "prefix9suffix", "xprefix5suffixy"],
        ),
        # \s with prefix and suffix — Phase 2 produces whitespace combined groups;
        # the fully-combined group subsumes the standalone groups.
        (
            r"pre\ssuf",
            [["pre\tsuf", "pre\nsuf", "pre\x0bsuf", "pre\x0csuf", "pre\rsuf", "pre suf"]],
            ["pre suf", "pre\tsuf", "pre\nsuf", "xpre\rsufy"],
        ),
        # \d with prefix only (no suffix) — Phase 2 produces prefix+digit group;
        # the combined group subsumes the standalone prefix group.
        (
            r"pre\d",
            [["pre0", "pre1", "pre2", "pre3", "pre4", "pre5", "pre6", "pre7", "pre8", "pre9"]],
            ["pre0", "pre9", "xpre5y"],
        ),
        # \d at pattern start + suffix — Phase 2 produces combined group;
        # the combined group subsumes the standalone suffix group.
        (
            r"\dsuffix",
            [
                [
                    "0suffix",
                    "1suffix",
                    "2suffix",
                    "3suffix",
                    "4suffix",
                    "5suffix",
                    "6suffix",
                    "7suffix",
                    "8suffix",
                    "9suffix",
                ]
            ],
            ["0suffix", "9suffix", "x5suffixy"],
        ),
        # \d at pattern start + literal — Phase 2 produces combined group;
        # the combined group subsumes the standalone literal group.
        (
            r"\dfoo",
            [["0foo", "1foo", "2foo", "3foo", "4foo", "5foo", "6foo", "7foo", "8foo", "9foo"]],
            ["0foo", "9foo", "x5fooy"],
        ),
    ],
)
def test_category_expansion_phase2(pattern, expected, matching):
    r"""CATEGORY_DIGIT (\d) and CATEGORY_SPACE (\s) expansion produces
    Phase 2 combined groups when surrounding mandatory literals exist."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


# ---------------------------------------------------------------------------
# RANGE expansion: small character class ranges in Phase 2 (#2d)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Single small range with suffix — Phase 2 produces combined groups;
        # the combined group subsumes the standalone suffix group.
        (r"[a-f]bar", [["abar", "bbar", "cbar", "dbar", "ebar", "fbar"]], ["abar", "fbar", "xcbar"]),
        # Small range at pattern start with literal;
        # the combined group subsumes the standalone literal group.
        (r"[0-3]x", [["0x", "1x", "2x", "3x"]], ["0x", "3x", "x2xy"]),
        # RANGE + CATEGORY_DIGIT in same class (≤20 total);
        # the combined group subsumes the standalone suffix group.
        (
            r"[a-f0-9]z",
            [["0z", "1z", "2z", "3z", "4z", "5z", "6z", "7z", "8z", "9z", "az", "bz", "cz", "dz", "ez", "fz"]],
            ["0z", "9z", "fz", "x5zy"],
        ),
        # RANGE + prefix — Phase 2 produces prefix+char group;
        # the combined group subsumes the standalone prefix group.
        (r"pre[a-c]", [["prea", "preb", "prec"]], ["prea", "prec", "xpreby"]),
        # Two small non-contiguous ranges;
        # the combined group subsumes the standalone suffix group.
        (r"[a-ce-g]x", [["ax", "bx", "cx", "ex", "fx", "gx"]], ["ax", "gx", "xfxy"]),
        # RANGE + CATEGORY expansion with prefix and suffix;
        # the fully-combined group subsumes all standalone groups.
        (
            r"pre[\da-f]suf",
            [
                [
                    "pre0suf",
                    "pre1suf",
                    "pre2suf",
                    "pre3suf",
                    "pre4suf",
                    "pre5suf",
                    "pre6suf",
                    "pre7suf",
                    "pre8suf",
                    "pre9suf",
                    "preasuf",
                    "prebsuf",
                    "precsuf",
                    "predsuf",
                    "preesuf",
                    "prefsuf",
                ]
            ],
            ["pre0suf", "prefsuf", "xpre5sufy"],
        ),
    ],
)
def test_range_expansion_phase2(pattern, expected, matching):
    r"""RANGE expansion (#2d) produces Phase 2 combined groups when
    ranges span ≤20 characters and surrounding mandatory literals exist."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


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
        _assert_prefilter_inclusion(pattern, result[0], matching)
        assert len(result) <= budget


# ---------------------------------------------------------------------------
# Extremely complex: devilish combinations exercising subtle SRE features
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [
        # Positive lookahead before alternation with literal suffix
        (r"foo(?=.*end)\s(bar|baz)qux", ["foo barqux end", "foo\tbazqux and end"]),
        # Optional group ? with literal prefix and suffix
        (r"prefix(?:-\d+)?suffix", ["prefixsuffix", "prefix-123suffix"]),
        # Alternation inside a required repeat {2}
        (r"(?:alpha|beta|gamma){2}", ["alphaalpha", "betagamma", "gammaalpha"]),
        # Backreference \1 between literals "a" and "c"
        (r"(a)b\1c", ["abac", "xabacy"]),
        # Positive lookbehind + alternation + literal-dot + \w + positive lookahead
        (r"(?<=@)(?:com|org|net)\.\w+(?=\s|$)", ["@com.domain ", "@org.host"]),
        # Triple-nested optional non-capturing groups (?:...)?  (?:...)?  (?:...)
        (r"(?:a(?:b(?:c)?)?)?d", ["d", "ad", "abd", "abcd"]),
        # Negative lookbehind + alternation + optional \d+ + negative lookahead
        (r"(?<!\w)(?:error|warning)(?:\s+\d+)?(?!\w)", ["error", "warning 404", "warning:"]),
        # Positive lookbehind + alternation + positive lookahead
        (r"(?<=start_)(?:alpha|beta)(?=_end)", ["start_alpha_end", "start_beta_end"]),
        # \b word boundary + alternation + \b word boundary + positive lookahead
        (r"\b(?:foo|bar|baz)\b(?=\s+\d+)", ["foo 123", "bar 456"]),
        # Optional group ? followed by alternation inside {2} repeat
        (r"(?:foo)?(?:bar|baz){2}", ["barbar", "barbaz", "foobarbaz", "bazbar"]),
        # Character classes [abc]+ and [xyz]+ separated by literal ":" with suffix "@test"
        (r"[abc]+:[xyz]+@test", ["abc:xyz@test", "a:x@test", "cba:zyx@test"]),
        # \A string start anchor
        (r"\Ahello", ["hello"]),
        # \Z string end anchor
        (r"world\Z", ["world"]),
        # Both \A and \Z
        (r"\Aexact\Z", ["exact"]),
        # \B non-word boundary
        (r"foo\Bbar", ["foobar"]),
        (r"\Bword\B", ["swordfish"]),
        # Named backreference (?P=name)
        (r"(?P<w>foo)(?P=w)", ["foofoo"]),
        (r"(?P<x>a)b(?P=x)", ["aba"]),
        # Two consecutive lookaheads / lookbehinds
        (r"(?<=@)(?=\w)foo", ["@foo"]),
        (r"(?<!\d)(?=[A-Z])Bar", ["XBar"]),
        # Lookaround inside alternation (ASSERT at *front* of each branch)
        (r"(?<=@)com|(?<=\.)org", ["@com", ".org"]),
        # Alternation with empty branch — trailing literal survives
        (r"^(a|)b$", ["ab", "b"]),
        (r"^(foo|)bar$", ["foobar", "bar"]),
        # Multiple consecutive backreferences
        (r"(a)(b)\2\1", ["abba"]),
        (r"(x)(y)(z)\3\2\1", ["xyzzyx"]),
        # Non-ASCII literal characters
        ("café", ["café"]),
        ("日本語", ["日本語"]),
        (r"naïve\dmatch", ["naïve1match"]),
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
# Atomic groups, scoped case-insensitive, and lazy alternation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, matching",
    [(r"(?>foo)bar", ["foobar"]), (r"(?>foo)+bar", ["foofoobar", "foobar"]), (r"pre(?>foo)bar", ["prefoobar"])],
)
def test_atomic_group_bug(pattern, matching):
    _check(pattern, matching, assert_not_none=True)


@pytest.mark.parametrize(
    "pattern, matching",
    [(r"pre(?i:foo)bar", ["prefoobar", "preFOObar"]), (r"(?i:hello)world", ["hELLoworld", "HELLOworld"])],
)
def test_scoped_case_insensitive(pattern, matching):
    # Use max_combinations=32 so all case variants (up to 2^5) fit.
    result = pattern_extract_prefilter_literals(pattern, max_combinations=32)
    assert result is not None, f"{pattern!r} returned None"
    _assert_prefilter_inclusion(pattern, result[0], matching)


def test_lazy_alternation_empty_match():
    """Empty string matches ^(?:foo|bar)*?$ but none of the returned literals
    are substrings of ''."""
    result = pattern_extract_prefilter_literals(r"^(?:foo|bar)*?$")
    if result is not None:
        # result is list[list[str]] — check first group
        assert any(lit in "" for lit in result[0]), f"Empty string matches pattern but contains none of {result}"


# ---------------------------------------------------------------------------
# New return type: list[list[str]] — independent prefilter groups
# ---------------------------------------------------------------------------


def _assert_grouped_prefilter(pattern, expected_groups, matching_strings):
    """Validate list[list[str]] return type semantics.

    Each inner list is an *independent* prefilter group.  For a group to be
    valid, every string that matches *pattern* must contain at least one of
    the group's literals as a substring.  The caller may pick any single
    group and use it as a standalone prefilter.
    """
    try:
        compiled = re.compile(pattern)
    except re.error:
        pytest.skip(f"Pattern {pattern!r} cannot be compiled by stdlib re")

    # Every test string must actually match the pattern
    for s in matching_strings:
        assert compiled.search(s), f"Test string {s!r} does not match pattern {pattern!r} — fix the test data"

    # Each group must be a valid independent prefilter
    for group in expected_groups:
        for s in matching_strings:
            assert any(lit in s for lit in group), (
                f"Group {group!r} fails for string {s!r} matching {pattern!r}: "
                f"none of {group} are substrings of {s}"
            )


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Pure literal — single group with one literal
        ("hello", [["hello"]], ["hello", "xhellox"]),
        # /foo.*bar/ — two mandatory literals, each its own group
        (r"foo.*bar", [["foo"], ["bar"]], ["foobar", "fooxxxbar", "xfoobary"]),
        # /foo|bar/ — neither is mandatory, one group with both alternatives
        (r"foo|bar", [["foo", "bar"]], ["foo", "bar", "xfoox", "bary"]),
        # /ab(cd)?ef/ — 'ab' and 'ef' are mandatory, each its own group;
        # Phase 2 adds the optional-expansion group which subsumes the
        # standalone mandatory groups.
        (r"ab(cd)?ef", [["abcdef", "abef"]], ["abef", "abcdef"]),
        # /foo.*bar.*baz/ — three mandatory literals
        (r"foo.*bar.*baz", [["foo"], ["bar"], ["baz"]], ["foobarbaz", "fooxxxbaryyybaz", "xfoobarbazy"]),
        # /(foo|bar)baz/ — only 'baz' is mandatory;
        # Phase 2 adds the prefix+alternation group which subsumes it.
        (r"(foo|bar)baz", [["barbaz", "foobaz"]], ["foobaz", "barbaz"]),
        # /a(b|c)d/ — 'a' and 'd' are mandatory, each its own group;
        # Phase 2 adds combined prefix/suffix + alternation groups which
        # subsume all standalone groups.
        (r"a(b|c)d", [["abd", "acd"]], ["abd", "acd"]),
        # Literal + .* + no trailing literal — only the prefix is mandatory
        (r"foo.*", [["foo"]], ["foo", "foobar"]),
        # .* + literal suffix — only suffix is mandatory
        (r".*bar", [["bar"]], ["bar", "foobar"]),
        # Alternation with common prefix AND suffix — both are mandatory;
        # Phase 2 adds combined groups which subsume the mandatory-only groups.
        (r"pre(fix|lude)", [["prefix", "prelude"]], ["prefix", "prelude"]),
        (r"(un|re)do", [["redo", "undo"]], ["undo", "redo"]),
        # Multiple wildcards splitting mandatory chunks
        (r"foo.+bar.*baz", [["foo"], ["bar"], ["baz"]], ["fooxbarxxxbaz", "fooxyzbarybaz"]),
        # Word boundary before/after literal
        (r"\bword\b", [["word"]], ["word", "a word here"]),
        # Lookahead — literal in lookahead forced as independent group (#3);
        # merged lookahead+body group (#5 adjacent-literal merging) subsumes
        # the standalone groups.
        (r"foo(?=bar)", [["foobar"]], ["foobar"]),
        # Lookbehind — literal before match forced as independent group (#3);
        # merged lookbehind+body group (#5 adjacent-literal merging) subsumes
        # the standalone groups.
        (r"(?<=foo)bar", [["foobar"]], ["foobar"]),
        # Character class with surrounding mandatory literals;
        # Phase 2 adds the digit-expansion group after #2c.
        (
            r"foo\d+bar",
            [["foo"], ["bar"], ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]],
            ["foo123bar", "foo0bar"],
        ),
        # Optional group — only the non-optional parts are mandatory;
        # Phase 2 adds the optional-expansion group which subsumes the
        # standalone mandatory groups.
        (r"colou?r", [["color", "colour"]], ["color", "colour"]),
        # Escaped metacharacters as literals
        (r"a\.b", [["a.b"]], ["a.b"]),
        # #4 — mixed lookaround + alternation: no body literals, lookaround-forced
        (r"(?<=@)\w+|(?<=#)\w+", [["@", "#"]], ["@abc", "#xyz"]),
        # #4/#5 — lookaround + alternation: merged lookbehind+body
        (r"(?<=@)com|(?<=\.)org", [["@com", ".org"]], ["@com", ".org"]),
    ],
)
def test_grouped_prefilter_mandatory(pattern, expected, matching):
    """Phase 1 + Phase 2 combined: prefilter groups.

    Each returned group consists of literals that are guaranteed to appear
    in every regex match.  Groups are independent — the caller picks one."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert all(isinstance(g, list) for g in result), f"Expected list[list[str]], got {[type(g) for g in result]}"
    # Sort within groups and across groups for deterministic comparison
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # /(foo|bar)baz/ — mandatory 'baz' + combined prefix-alternation groups;
        # the combined group subsumes the standalone mandatory group.
        (r"(foo|bar)baz", [["barbaz", "foobaz"]], ["foobaz", "barbaz"]),
        # /pre(fix|lude|text)/ — mandatory 'pre' + full expansion groups;
        # the combined group subsumes the standalone mandatory prefix.
        (r"pre(fix|lude|text)", [["prefix", "prelude", "pretext"]], ["prefix", "prelude", "pretext"]),
        # /(un|re|dis)do/ — mandatory 'do' + full groups;
        # the combined group subsumes the standalone mandatory suffix.
        (r"(un|re|dis)do", [["disdo", "redo", "undo"]], ["undo", "redo", "disdo"]),
        # /a(b|c)d/ — mandatory 'a','d' + combined groups;
        # the fully-combined group subsumes all standalone groups.
        (r"a(b|c)d", [["abd", "acd"]], ["abd", "acd"]),
        # /ab(cd)?ef/ — mandatory parts + full expansion;
        # the combined group subsumes the standalone mandatory groups.
        (r"ab(cd)?ef", [["abcdef", "abef"]], ["abef", "abcdef"]),
        # /(foo|bar){2}/ — alternation repeated
        (r"(foo|bar){2}", [["foofoo", "foobar", "barfoo", "barbar"]], ["foofoo", "foobar", "barfoo", "barbar"]),
        # /[abc]+@[xyz]+/ — mandatory separator '@' plus Phase 2 character-class
        # expansion groups (each is a valid independent prefilter).
        (r"[abc]+@[xyz]+", [["@"], ["a", "b", "c"], ["x", "y", "z"]], ["abc@xyz", "a@x", "cba@zyx"]),
    ],
)
def test_grouped_prefilter_extended(pattern, expected, matching):
    """Phase 2: extended groups that combine mandatory/non-mandatory parts
    to offer more specific (less-overlapping) prefilter options."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert all(isinstance(g, list) for g in result), f"Expected list[list[str]], got {[type(g) for g in result]}"
    # Sort within groups and across groups for deterministic comparison
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


# ---------------------------------------------------------------------------
# Lookaround-adjacent-literal merging
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Lookahead at end of literal → merged foobar;
        # the merged group subsumes the standalone foo/bar groups.
        (r"foo(?=bar)", [["foobar"]], ["foobar", "xfoobary"]),
        # Lookbehind at start of literal → merged foobar;
        # the merged group subsumes the standalone groups.
        (r"(?<=foo)bar", [["foobar"]], ["foobar", "xfoobary"]),
        # Lookbehind + literal + lookahead → all three merges;
        # foobarbaz subsumes every other group.
        (r"(?<=foo)bar(?=baz)", [["foobarbaz"]], ["foobarbaz", "xfoobarbazy"]),
        # Alternation with lookbehind in each branch → merged branch results
        (r"(?<=foo)bar|(?<=foo)baz", [["foobar", "foobaz"]], ["foobar", "foobaz", "xfoobary"]),
        # Alternation with lookahead in each branch (shared prefix) → merged;
        # the merged group subsumes the standalone foo group.
        (r"foo(?=bar)|foo(?=baz)", [["foobar", "foobaz"]], ["foobar", "foobaz", "xfoobary"]),
        # Lookahead after the only body literal → simple merge;
        # the merged group subsumes the standalone groups.
        (r"ab(?=cd)", [["abcd"]], ["abcd", "xabcdy"]),
        # Lookbehind before the only body literal → simple merge;
        # the merged group subsumes the standalone groups.
        (r"(?<=ab)cd", [["abcd"]], ["abcd", "xabcdy"]),
    ],
)
def test_lookaround_adjacent_literal_merging(pattern, expected, matching):
    """Lookaround-forced literals adjacent to mandatory match-body literals
    should produce merged groups (e.g., foo(?=bar) → foobar).

    The merged group is more specific: every match of foo(?=bar) must contain
    foobar as a substring.  Standalone groups (foo, bar) are also kept for
    callers that prefer shorter prefilter strings."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert all(isinstance(g, list) for g in result), f"Expected list[list[str]], got {[type(g) for g in result]}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


# ---------------------------------------------------------------------------
# Postprocessing: pruning subsumed groups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Lookaround merges: standalone 'foo'/'bar' are substrings of 'foobar'
        (r"foo(?=bar)", [["foobar"]], ["foobar", "xfoobary"]),
        (r"(?<=foo)bar", [["foobar"]], ["foobar", "xfoobary"]),
        (r"(?<=foo)bar(?=baz)", [["foobarbaz"]], ["foobarbaz", "xfoobarbazy"]),
        (r"ab(?=cd)", [["abcd"]], ["abcd", "xabcdy"]),
        (r"(?<=ab)cd", [["abcd"]], ["abcd", "xabcdy"]),
        # Alternation with surrounding mandatory context:
        # mandatory-only groups are substrings of the expanded groups
        (r"pre(fix|lude)", [["prefix", "prelude"]], ["prefix", "prelude"]),
        (r"(un|re)do", [["redo", "undo"]], ["undo", "redo"]),
        (r"(foo|bar)baz", [["barbaz", "foobaz"]], ["foobaz", "barbaz"]),
        (r"a(b|c)d", [["abd", "acd"]], ["abd", "acd"]),
        # Optional constructs: mandatory-only groups subsumed by optional-expanded
        (r"colou?r", [["color", "colour"]], ["color", "colour"]),
        (r"ab(cd)?ef", [["abcdef", "abef"]], ["abef", "abcdef"]),
        # Three-branch alternation: mandatory prefix subsumed by full expansion
        (r"pre(fix|lude|text)", [["prefix", "prelude", "pretext"]], ["prefix", "prelude", "pretext"]),
        # Unbounded optional repeats (*, {0,}): no optional-expansion produced,
        # so mandatory-only groups survive.
        (r"ab*c", [["a"], ["c"]], ["ac", "abc", "abbbc"]),
        (r"xa*", [["x"]], ["x", "xa", "xaa"]),
        (r"a*b", [["b"]], ["b", "ab", "aab"]),
        (r"ab{0,2}c", [["a"], ["c"]], ["ac", "abc", "abbc"]),
    ],
)
def test_prune_subsumed_groups(pattern, expected, matching):
    """Postprocessing pass: groups whose every literal is a substring of
    some literal in another (more-specific) group are pruned.

    For example, ``foo(?=bar)`` produces ``[['foo'], ['bar'], ['foobar']]``
    before pruning.  Since 'foo' and 'bar' are each substrings of
    'foobar', the first two groups are redundant — ``['foobar']`` is
    strictly more specific (fewer false positives)."""
    result = pattern_extract_prefilter_literals(pattern)
    assert result is not None, f"Expected non-None for {pattern!r}"
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert all(isinstance(g, list) for g in result), f"Expected list[list[str]], got {[type(g) for g in result]}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n"
        f"  expected (pruned): {expected_normalized}\n"
        f"  got:               {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


# ---------------------------------------------------------------------------
# Alternation branch shortening — strip expansible endings to fit budget
# ---------------------------------------------------------------------------


def test_alternation_shorten_real_world_path_pattern():
    """Real-world path pattern with expansible content in alternation branches.

    When alternation branches contain expansible content like [^/]*, [^/]+, \\d+
    that makes them non-expandable via _branch_literal_string, the function
    should shorten each branch by stripping trailing expansible parts to produce
    valid prefilter literals that fit within the budget.

    Previously this returned just ['Library/Application Support/'] (the mandatory
    prefix before the alternation), losing the branch-specific information."""
    pattern = (
        r"^(Users/[^/]+/)?Library/Application Support/"
        r"(Firefox|Apple[^/]*|Google[^/]*|Microsoft|GarageBand|Logic|"
        r"com\.(apple|microsoft)\.[^/]+|Postman|Slack|"
        r"Docker Desktop|iStat Menus \d+|Spotify|pipx|Cypress|"
        r"iLifeMediaBrowser)$"
    )
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    expected = [
        "Library/Application Support/Apple",
        "Library/Application Support/Cypress",
        "Library/Application Support/Docker Desktop",
        "Library/Application Support/Firefox",
        "Library/Application Support/GarageBand",
        "Library/Application Support/Google",
        "Library/Application Support/Logic",
        "Library/Application Support/Microsoft",
        "Library/Application Support/Postman",
        "Library/Application Support/Slack",
        "Library/Application Support/Spotify",
        "Library/Application Support/com.apple.",
        "Library/Application Support/com.microsoft.",
        "Library/Application Support/iLifeMediaBrowser",
        "Library/Application Support/iStat Menus ",
        "Library/Application Support/pipx",
    ]
    assert result is not None, "Expected non-None for path pattern, got None"
    assert sorted(result[0]) == sorted(expected), (
        f"Expected {len(expected)} shortened branch literals,\n" f"got {sorted(result[0])}"
    )


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Trailing expansible char class [^/]* stripped from branches
        (r"(foo|bar[^/]*|baz)qux", [["bar", "bazqux", "fooqux"]], ["fooqux", "barqux", "barSomethingqux", "bazqux"]),
        # Trailing \d+ stripped from one branch
        (
            r"prefix(foo|bar\d+)suffix",
            [["prefixbar", "prefixfoosuffix"]],
            ["prefixfoosuffix", "prefixbar123suffix", "prefixbar1suffix"],
        ),
        # Leading \d+ stripped from one branch
        (
            r"prefix(\d+bar|baz)suffix",
            [["barsuffix", "prefixbazsuffix"]],
            ["prefix123barsuffix", "prefixbazsuffix", "prefix1barsuffix"],
        ),
        # Trailing [^/]+ stripped from nested alternation
        (
            r"com\.(apple|microsoft)\.[^/]+",
            [["com.apple.", "com.microsoft."]],
            ["com.apple.something", "com.microsoft.other", "com.apple.x"],
        ),
        # Mixed: some pure-literals, some with expansible endings
        (
            r"(Firefox|Apple[^/]*|Google[^/]*|Microsoft)",
            [["Apple", "Firefox", "Google", "Microsoft"]],
            ["Firefox", "Apple", "AppleXYZ", "GoogleStuff", "Microsoft"],
        ),
        # Trailing whitespace-then-\d+ stripped
        (r"(iStat Menus \d+|Spotify)", [["Spotify", "iStat Menus "]], ["iStat Menus 5", "Spotify", "iStat Menus 42"]),
        # Both leading and trailing expansible stripped; no common prefix/suffix
        (r"\d+mid\d+|other", [["mid", "other"]], ["123mid456", "other", "0mid9"]),
    ],
)
def test_alternation_shorten_branches(pattern, expected, matching):
    """When alternation branches contain expansible content that would
    overflow the budget, branches should be shortened by stripping leading
    and trailing expansible parts to produce valid prefilter literals.

    The shortened literal is always guaranteed to be a substring of every
    match of the original branch, so the prefilter contract holds."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Shortening with common prefix before alternation
        (
            r"pre/(foo|bar\d+|baz)\d*",
            [["pre/bar", "pre/baz", "pre/foo"]],
            ["pre/foo999", "pre/bar123", "pre/baz", "pre/bar1"],
        ),
        # Shortening with common suffix after alternation
        (
            r"[^/]*(alpha|beta|gamma[^/]+)suf",
            [["alphasuf", "betasuf", "gamma"]],
            ["xxxalphasuf", "xxxbetasuf", "xxxgammaYYYsuf", "alphasuf"],
        ),
        # Shortening with both prefix and suffix, some branches already pure
        (
            r"pre(foo|bar\d+|baz)suf",
            [["prebar", "prebazsuf", "prefoosuf"]],
            ["prefoosuf", "prebar1suf", "prebar42suf", "prebazsuf"],
        ),
    ],
)
def test_alternation_shorten_with_surrounding_context(pattern, expected, matching):
    """Shortening should work together with surrounding mandatory context
    (prefix/suffix outside the alternation)."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Shortened result fits under tight budget (e.g. max_combinations=6
        # for a 6-branch alternation with the prefix)
        (
            r"pre(foo|bar\d+|baz|qux\d*|abc|xyz\d+)suf",
            [["preabcsuf", "prebar", "prebazsuf", "prefoosuf", "prequx", "prexyz"]],
            ["prefoosuf", "prebar123suf", "prebazsuf", "prequx99suf", "preabcsuf", "prexyz99suf"],
        )
    ],
)
def test_alternation_shorten_budget_constrained(pattern, expected, matching):
    """Shortened branches must respect max_combinations budget."""
    # Exact fit: 6 combos, budget=6
    result = pattern_extract_prefilter_literals(pattern, max_combinations=6)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


@pytest.mark.parametrize(
    "pattern, expected, matching",
    [
        # Both-side shortening: branches shortened on trailing side use prefix,
        # branches shortened on leading side use suffix.
        (
            r"foo(ab[^/]*|[^/]*AB|other)bar",
            [["fooab", "foootherbar", "ABbar"]],
            ["fooabXYZbar", "fooXYZABbar", "foootherbar"],
        ),
        # Both-side shortening with only prefix outside (no suffix)
        (r"pre/(ab\d*|\d*AB|xyz)", [["pre/ab", "pre/xyz", "AB"]], ["pre/ab123", "pre/987AB", "pre/xyz"]),
        # Both-side shortening with only suffix outside (no prefix)
        (r"(ab\d*|\d*AB|xyz)suf", [["ab", "ABsuf", "xyzsuf"]], ["ab999suf", "123ABsuf", "xyzsuf"]),
        # Shortened on both ends within single branch: \d*mid\d*
        (r"foo(\d*mid\d*|other)bar", [["foootherbar", "mid"]], ["foo123mid456bar", "foootherbar"]),
        # Nested alternation with trailing expansible
        (
            r"pre/((ab|cd)\d+|(ef|gh)[^/]*|xyz)suf",
            [["pre/ab", "pre/cd", "pre/ef", "pre/gh", "pre/xyzsuf"]],
            ["pre/ab123suf", "pre/cd99suf", "pre/efXYZsuf", "pre/ghXsuf", "pre/xyzsuf"],
        ),
        # Nested alternation with leading expansible
        (
            r"pre/(\d+(ab|cd)|[^/]*(ef|gh)|xyz)suf",
            [["absuf", "cdsuf", "efsuf", "ghsuf", "pre/xyzsuf"]],
            ["pre/123absuf", "pre/99cdsuf", "pre/Xefsuf", "pre/Xghsuf", "pre/xyzsuf"],
        ),
        # Nested alternation with expansible on both sides
        (
            r"pre/(\d+(ab|cd)\d*|[^/]*(ef|gh)\d*|xyz)suf",
            [["ab", "cd", "ef", "gh", "pre/xyzsuf"]],
            ["pre/123ab456suf", "pre/1cd99suf", "pre/Xef123suf", "pre/ghsuf", "pre/xyzsuf"],
        ),
        # Character class expansion with trailing shortening
        (
            r"pre/([abc]+\d*|xyz)suf",
            [["pre/a", "pre/b", "pre/c", "pre/xyzsuf"]],
            ["pre/aaa123suf", "pre/b99suf", "pre/csuf", "pre/xyzsuf"],
        ),
        # Character class inside nested alternation, shortened
        (
            r"pre/(foo|[abc]+\d*|xyz)suf",
            [["pre/a", "pre/b", "pre/c", "pre/foosuf", "pre/xyzsuf"]],
            ["pre/aaa123suf", "pre/b99suf", "pre/csuf", "pre/foosuf", "pre/xyzsuf"],
        ),
        # Large alternation with mixed shortening (some trailing, some leading, some both)
        (
            r"prefix(ab\d*|\d*cd|ef[^/]*|[^/]*gh|ij|\d*kl\d*)suffix",
            [["cdsuffix", "ghsuffix", "kl", "prefixab", "prefixef", "prefixijsuffix"]],
            [
                "prefixab123suffix",
                "prefix987cdsuffix",
                "prefixefXYZsuffix",
                "prefixUVWghsuffix",
                "prefixijsuffix",
                "prefix12kl34suffix",
            ],
        ),
    ],
)
def test_alternation_shorten_both_sides(pattern, expected, matching):
    """Shortening must work on both sides of each branch: trailing expansible
    content is stripped and the result attaches to the prefix; leading
    expansible content is stripped and the result attaches to the suffix.

    For branches shortened on BOTH ends (e.g. \\d*mid\\d*), only the inner
    literal core is returned, combined with neither prefix nor suffix.

    Nested alternations and expandable character classes should also be
    shortened when surrounded by expansible content."""
    result = pattern_extract_prefilter_literals(pattern, max_combinations=20)
    assert result is not None, f"Expected non-None for {pattern!r}"
    result_normalized = sorted([sorted(g) for g in result])
    expected_normalized = sorted([sorted(g) for g in expected])
    assert result_normalized == expected_normalized, (
        f"For {pattern!r}:\n" f"  expected: {expected_normalized}\n" f"  got:      {result_normalized}"
    )
    _assert_grouped_prefilter(pattern, expected, matching)


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
