import fnmatch
import time
import hashlib
import posixpath
import re
import sys
import platform
import unicodedata
import warnings
from daachorse import DoubleArrayAhoCorasick, CharwiseDoubleArrayAhoCorasick
from collections import namedtuple
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from operator import itemgetter
from functools import cache
from itertools import product

_ITEMGETTER_2 = itemgetter(2)


if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from .helpers import clean_lines, shellpattern, pattern_extract_prefilter_literals
from .helpers.argparsing import Action, ArgumentTypeError
from .helpers.errors import Error


def parse_patternfile_line(line, roots, ie_commands, fallback):
    """Parse a pattern-file line and act depending on which command it represents."""
    ie_command = parse_inclexcl_command(line, fallback=fallback)
    if ie_command.cmd is IECommand.RootPath:
        roots.append(ie_command.val)
    elif ie_command.cmd is IECommand.PatternStyle:
        fallback = ie_command.val
    else:
        # it is some kind of include/exclude command
        ie_commands.append(ie_command)
    return fallback


def load_pattern_file(fileobj, roots, ie_commands, fallback=None):
    if fallback is None:
        fallback = ShellPattern  # ShellPattern is defined later in this module
    for line in clean_lines(fileobj):
        fallback = parse_patternfile_line(line, roots, ie_commands, fallback)


def load_exclude_file(fileobj, patterns):
    for patternstr in clean_lines(fileobj):
        patterns.append(parse_exclude_pattern(patternstr))


class ArgparsePatternAction(Action):
    def __init__(self, nargs=1, **kw):
        super().__init__(nargs=nargs, **kw)

    def __call__(self, parser, args, values, option_string=None):
        parse_patternfile_line(values[0], args.pattern_roots, args.patterns, ShellPattern)


class ArgparsePatternFileAction(Action):
    def __init__(self, nargs=1, **kw):
        super().__init__(nargs=nargs, **kw)

    def __call__(self, parser, args, values, option_string=None):
        """Load and parse patterns from a file.
        Lines empty or starting with '#' after stripping whitespace on both line ends are ignored.
        """
        filename = values[0]
        try:
            with open(filename) as f:
                self.parse(f, args)
        except FileNotFoundError as e:
            raise Error(str(e))

    def parse(self, fobj, args):
        load_pattern_file(fobj, args.pattern_roots, args.patterns)


class ArgparseExcludeFileAction(ArgparsePatternFileAction):
    def parse(self, fobj, args):
        load_exclude_file(fobj, args.patterns)


class PatternMatcher:
    """Represents a collection of pattern objects to match paths against.

    *fallback* is a boolean value that *match()* returns if no matching patterns are found.

    """

    def __init__(self, roots, fallback=None):
        self._roots = [root.rstrip("/") + "/" for root in roots]
    # def __init__(self, fallback=None):
        self._items = []

        # Value to return from match function when none of the patterns match.
        self.fallback = fallback

        # optimizations
        self._path_full_patterns = {}  # full path -> return value
        self._path_full_patterns__get = self._path_full_patterns.get

        # indicates whether the last match() call ended on a pattern for which
        # we should recurse into any matching folder.  Will be set to True or
        # False when calling match().
        # self.recurse_dir = None

        # Whether to recurse into directories when no match is found.
        # This must be True so that include patterns inside excluded directories
        # work correctly (e.g. "+ /excluded_dir/important" inside "- /excluded_dir").
        # self.recurse_dir_default = True

        self.include_patterns = []

        # self._prefilter_mapping = []
        # self._prefilter_literals = []
        # self._always_recheck_patterns = []
        # self._automaton = None
        self._match_pattern = None
        self._default_match = None

    def empty(self):
        return not len(self._items) and not len(self._path_full_patterns)

    def _add(self, patterns, cmds):
        """*cmd* is an IECommand value."""
        for pattern, cmd in zip(patterns, cmds):
            if isinstance(pattern, PathFullPattern):
                self._path_full_patterns[pattern.pattern] = pattern.match_obj
            else:
                self._items.append(pattern)
        # self._automaton = None  # invalidate cached automaton
        # self._match_pattern = None

    PATTERN_AUTOMATON_MAGIC = b"BORG-PATTERNS-DB"
    PATTERN_AUTOMATON_VERSION = b"1"

    def _finalize_matcher(self):
        """Compile or load cached hyperscan database for the current set of patterns."""
        if not self._items:
            self._match_pattern = lambda _path: None
            return

        automaton = None
        if True:
            t0 = time.time_ns()
            items_hash = (
                hashlib.sha256(
                    self.PATTERN_AUTOMATON_MAGIC
                    + b"\0"
                    + self.PATTERN_AUTOMATON_VERSION
                    + b"\0"
                    + (
                        platform.processor()
                        + "\0"
                        + platform.system()
                        + "\0"
                        + repr(self._roots)
                        + "\0"
                        + repr([(p.regex_pattern) for p in self._items])
                    ).encode()
                )
                .hexdigest()
                .encode()
            )

            cache_automaton_path = Path("patterns.db")

            try:
                with open(cache_automaton_path, "rb") as f:
                    cache_content = f.read()
                    # print(repr(cache_content))
                    if len(cache_content) <= (
                        len(self.PATTERN_AUTOMATON_MAGIC)
                        + len(self.PATTERN_AUTOMATON_VERSION)
                        + len(items_hash)
                        + len(DoubleArrayAhoCorasick.__name__)
                        + 4
                    ):
                        # print("abc")
                        raise RuntimeError("abc")

                    # magic, version, hash, cached_automaton_type, compressed_content = cache_content.split(b"\0", 4)
                    magic, version, hash, cached_automaton_type, always_recheck_indexes, automaton_content = cache_content.split(b"\0", 5)
                    # print(f"{self.PATTERN_AUTOMATON_MAGIC} {'==' if self.PATTERN_AUTOMATON_MAGIC == magic else '!='} {magic}")
                    # print(f"{self.PATTERN_AUTOMATON_VERSION} {'==' if self.PATTERN_AUTOMATON_VERSION == version else '!='} {version}")
                    # print(f"{items_hash} {'==' if items_hash == hash else '!='} {hash}")
                    if (
                        magic != self.PATTERN_AUTOMATON_MAGIC
                        or version != self.PATTERN_AUTOMATON_VERSION
                        or hash != items_hash
                    ):
                        # print("def")
                        raise RuntimeError("def")

                    # print(f"{cached_automaton_type} {'==' if cached_automaton_type != DoubleArrayAhoCorasick.__name__.encode() else '!='} {DoubleArrayAhoCorasick.__name__.encode()}")
                    if cached_automaton_type != DoubleArrayAhoCorasick.__name__.encode():
                        # print("ghi")
                        raise RuntimeError("ghi")

                    print(f"Reusing patterns automaton={hash}")

                    # always_recheck_indexes, automaton_content = zstd.decompress(compressed_content).split(b"\0", 1)

                    always_recheck_patterns = [
                        (None, None, int(istr)) for istr in always_recheck_indexes.split(b",") if istr
                    ]
                    automaton = DoubleArrayAhoCorasick.deserialize(automaton_content)

                    print(f"Pattern reuse finished after {(time.time_ns() - t0) / 1000000000:02f}s")
            except (FileNotFoundError, RuntimeError):
                print(f"Compiling new patterns automaton={items_hash}")

        if not automaton:
            print("Compiling new patterns")

            t0 = time.time_ns()

            prefilter_patterns = []
            always_recheck_patterns = []
            for i, pattern in enumerate(self._items):
                prefilter_candidates = pattern_extract_prefilter_literals(pattern.regex_pattern)
                if prefilter_candidates is None:
                    print(f"No prefilter candidates for {pattern.regex_pattern!r}")
                    always_recheck_patterns.append((None, None, i))
                    continue

                # print(prefilter_candidates)
                if len(prefilter_candidates) > 1:
                    matches_any_root = []
                    matches_no_root = []
                    for candidate in prefilter_candidates:
                        matches = False
                        for lit, root in product(candidate, self._roots):
                            if lit in root:
                                matches = True
                                break
                        if matches:
                            matches_any_root.append(candidate)
                        else:
                            matches_no_root.append(candidate)
                    if matches_any_root and matches_no_root:
                        print(
                            f"{matches_any_root} has root matches, so keeping only prefilter candidates {matches_no_root}"
                        )
                        prefilter_candidates = matches_no_root

                prefilter_literals = max(prefilter_candidates, key=lambda literals: sum(len(lit) for lit in literals))

                # print(prefilter_candidates)
                # print(prefilter_literals)
                # sys.exit(1)
                prefilter_patterns.extend([(literal.encode(), i) for literal in prefilter_literals])

            # print(prefilter_patterns)
            automaton = DoubleArrayAhoCorasick.build_with_values(prefilter_patterns)

            print(f"Pattern compile finished after {(time.time_ns() - t0) / 1000000000:02f}s")
            # print(self._always_recheck_patterns)

            if True:
                # Cache compiled database along with prefilter status
                with open(cache_automaton_path, "wb") as f:
                    f.write(
                        b"\0".join([
                            self.PATTERN_AUTOMATON_MAGIC,
                            self.PATTERN_AUTOMATON_VERSION,
                            items_hash,
                            automaton.__class__.__name__.encode(),
                            b",".join(str(idx).encode() for _, _, idx in always_recheck_patterns),
                            automaton.serialize()
                        ])
                        # + zstd.compress(
                        #     b",".join(str(idx).encode() for _, _, idx in always_recheck_patterns)
                        #     + b"\0"
                        #     + automaton.serialize(),
                        #     level=5,
                        # )
                    )

        items__getitem = self._items.__getitem__
        automaton__find_overlapping = automaton.find_overlapping
        if always_recheck_patterns:

            def match_pattern(path):
                nonlocal items__getitem, automaton__find_overlapping, always_recheck_patterns

                automaton_matches = automaton__find_overlapping(path.encode())
                if automaton_matches:
                    potential_matches = always_recheck_patterns + automaton_matches
                else:
                    potential_matches = always_recheck_patterns

                if len(potential_matches) == 1:
                    match_start, match_end, match_idx = potential_matches[0]
                    item = items__getitem(match_idx)
                    if item.recheck(path, match_start, match_end):
                        return item.match_obj

                else:
                    last_seen_idx = None
                    for match_start, match_end, match_idx in sorted(potential_matches, key=_ITEMGETTER_2):
                        if last_seen_idx == match_idx:
                            continue
                        last_seen_idx = match_idx

                        item = items__getitem(match_idx)
                        if item.recheck(path, match_start, match_end):
                            return item.match_obj

                return None

        else:

            def match_pattern(path):
                nonlocal automaton__find_overlapping

                potential_matches = automaton__find_overlapping(path.encode())
                if not potential_matches:
                    return None

                nonlocal items__getitem, always_recheck_patterns

                if len(potential_matches) == 1:
                    match_start, match_end, match_idx = potential_matches[0]
                    item = items__getitem(match_idx)
                    if item.recheck(path, match_start, match_end):
                        return item.match_obj

                else:
                    last_seen_idx = None
                    for match_start, match_end, match_idx in sorted(potential_matches, key=_ITEMGETTER_2):
                        if last_seen_idx == match_idx:
                            continue
                        last_seen_idx = match_idx

                        item = items__getitem(match_idx)
                        if item.recheck(path, match_start, match_end):
                            return item.match_obj

                return None

        self._match_pattern = match_pattern
        self._default_match = resolve_match_object(include=self.fallback, recurse=True)

    def add(self, patterns, cmd):
        """Add list of patterns to internal list. *cmd* indicates whether the
        pattern is an include/exclude pattern, and whether recursion should be
        done on excluded folders.
        """
        self._add(patterns, [cmd for _ in patterns])

    def add_includepaths(self, include_paths):
        """Used to add inclusion-paths from args.paths (from the command line)."""
        include_patterns = [parse_pattern(p, include=True, fallback=PathPrefixPattern) for p in include_paths]
        self.add(include_patterns, IECommand.Include)
        self.fallback = not include_patterns
        self.include_patterns = include_patterns

    def get_unmatched_include_patterns(self):
        """Note that this only returns patterns added via *add_includepaths*, and it
        won't return PathFullPattern patterns, as we do not maintain match_count for them.
        """
        # return [p for p in self.include_patterns if p.match_count == 0 and not isinstance(p, PathFullPattern)]
        return []

    def add_inclexcl(self, patterns):
        """Add list of patterns (of type CmdTuple) to internal list."""
        patterns, cmds = zip(*patterns)
        self._add(patterns, cmds)

    def match(self, path):
        """
        Return a Match object with information about how to process the
        given path. The Match object will be that of the first pattern to match
        the path, or a fallback Match if no pattern matched.
        """
        path = normalize_path(path).lstrip("/")

        return self._path_full_patterns__get(path, None) or self._match_pattern(path) or self._default_match


@contextmanager
def setup_pattern_matcher(fallback=None, roots=None):
    """Context manager for pattern matching with hyperscan database caching.

    Usage:
        with setup_pattern_matcher(fallback=True) as matcher:
            matcher.add_inclexcl(patterns)
            matcher.add_includepaths(paths)
        # matcher.match(...) can be called after the with block
    """
    matcher = PatternMatcher(fallback=fallback, roots=roots)
    yield matcher
    matcher._finalize_matcher()


def normalize_path(path):
    """normalize paths for MacOS (but do nothing on other platforms)"""
    # HFS+ converts paths to a canonical form, so users shouldn't be required to enter an exact match.
    # Windows and Unix filesystems allow different forms, so users always have to enter an exact match.
    return unicodedata.normalize("NFD", path) if sys.platform == "darwin" else path


pattern_id_counter = 0


class PatternBase:
    """Shared logic for inclusion/exclusion patterns."""

    PREFIX: str = None

    def __init__(self, pattern, include, recurse_dir=False):
        global pattern_id_counter

        self.pattern_orig = pattern
        # self.match_count = 0

        self.id = pattern_id_counter
        pattern_id_counter += 1

        pattern = normalize_path(pattern)
        self._prepare(pattern)
        self.match_obj = resolve_match_object(include=include, recurse=recurse_dir)

    def match(self, path, normalize=True):
        """Return a boolean indicating whether *path* is matched by this pattern.

        If normalize is True (default), the path will get normalized using normalize_path(),
        otherwise it is assumed that it already is normalized using that function.
        """
        # print(f"Slow-matching {self.regex_pattern} against '{path}'")
        if normalize:
            path = normalize_path(path)
        matches = self.regex.search(path) is not None
        # if matches:
        #     self.match_count += 1
        return matches

    def recheck(self, path, match_start, match_end):
        return self._recheck(path, match_start, match_end)

    def __repr__(self):
        return f"{type(self)}({self.pattern})"

    def __str__(self):
        return self.pattern_orig

    def _prepare(self, pattern):
        "Should set the value of self.pattern"
        raise NotImplementedError

    def _recheck(self, path, match_start, match_end):
        raise NotImplementedError


class PathFullPattern(PatternBase):
    """Full match of a path."""

    PREFIX = "pf"

    def _prepare(self, pattern):
        self.pattern = posixpath.normpath(pattern).lstrip("/")  # / at beginning is removed
        self.regex_pattern = r"\A" + re.escape(self.pattern) + r"\Z"

    def _recheck(self, path, match_start, match_end):
        return match_start == 0 and match_end == len(path)


# For PathPrefixPattern, FnmatchPattern and ShellPattern, we require that the pattern either match the whole path
# or an initial segment of the path up to but not including a path separator. To unify the two cases, we add a path
# separator to the end of the path before matching.


class PathPrefixPattern(PatternBase):
    """Literal files or directories listed on the command line
    for some operations (e.g. extract, but not create).
    If a directory is specified, all paths that start with that
    path match as well.  A trailing slash makes no difference.
    """

    PREFIX = "pp"

    def _prepare(self, pattern):
        self.pattern = (posixpath.normpath(pattern).rstrip("/") + "/").lstrip("/")  # / at beginning is removed
        self.regex_pattern = r"\A" + re.escape(self.pattern)

    def _recheck(self, _path, match_start, _match_end):
        return match_start == 0


class FnmatchPattern(PatternBase):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """

    PREFIX = "fm"

    def _prepare(self, pattern):
        if pattern.endswith("/"):
            pattern = posixpath.normpath(pattern).rstrip("/") + "/*/"
        else:
            pattern = posixpath.normpath(pattern) + "/*"

        self.pattern = pattern.lstrip("/")  # / at beginning is removed

        # fnmatch and re.match both cache compiled regular expressions.
        # Nevertheless, this is about 10 times faster.
        self.regex_pattern = fnmatch.translate(self.pattern)
        self.regex = re.compile(self.regex_pattern)

    def _recheck(self, path, match_start, match_end):
        return self.regex.search(path) is not None


class ShellPattern(PatternBase):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """

    PREFIX = "sh"

    def _prepare(self, pattern):
        if pattern.endswith("/"):
            pattern = posixpath.normpath(pattern).rstrip("/") + "?"
            match_end = r"\Z"
        else:
            pattern = posixpath.normpath(pattern) + r"/"
            match_end = ""

        self.pattern = pattern.lstrip("/")  # / at beginning is removed
        spattern = shellpattern.translate(self.pattern, match_end=match_end)
        self.regex_pattern = rf"{spattern[:5]}\A{spattern[5:]}"
        # print(self.regex_pattern)
        # sys.exit(1)
        if self.regex_pattern.endswith("/"):
            self.regex_pattern = self.regex_pattern[:-1] + r"\Z"
        # print(self.regex_pattern)
        self.regex = re.compile(self.regex_pattern)

    def _recheck(self, path, match_start, match_end):
        return self.regex.search(path) is not None


class RegexPattern(PatternBase):
    """Regular expression to exclude."""

    PREFIX = "re"

    def _prepare(self, pattern):
        self.pattern = pattern  # / at beginning is NOT removed
        self.regex_pattern = pattern
        self.regex = re.compile(self.regex_pattern)

    def _recheck(self, path, match_start, match_end):
        return self.regex.search(path) is not None


_PATTERN_CLASSES = {FnmatchPattern, PathFullPattern, PathPrefixPattern, RegexPattern, ShellPattern}

_PATTERN_CLASS_BY_PREFIX = {i.PREFIX: i for i in _PATTERN_CLASSES}

CmdTuple = namedtuple("CmdTuple", "val cmd")
Match = namedtuple("Match", ["include", "recurse"])


@cache
def resolve_match_object(include, recurse):
    return Match(include, recurse)


class IECommand(Enum):
    """A command that an InclExcl file line can represent."""

    RootPath = 1
    PatternStyle = 2
    Include = 3
    Exclude = 4
    ExcludeNoRecurse = 5

    @property
    def is_include(self):
        return self is IECommand.Include


def command_recurses_dir(cmd):
    if cmd is IECommand.ExcludeNoRecurse:
        return False
    if cmd is IECommand.Include or cmd is IECommand.Exclude:
        return True
    raise ValueError(f"command_recurses_dir: unexpected command: {cmd!r}")


def get_pattern_class(prefix):
    try:
        return _PATTERN_CLASS_BY_PREFIX[prefix]
    except KeyError:
        raise ValueError(f"Unknown pattern style: {prefix}") from None


def parse_pattern(pattern, include, fallback=FnmatchPattern, recurse_dir=True):
    """Read pattern from string and return an instance of the appropriate implementation class."""
    if len(pattern) > 2 and pattern[2] == ":" and pattern[:2].isalnum():
        (style, pattern) = (pattern[:2], pattern[3:])
        cls = get_pattern_class(style)
    else:
        cls = fallback
    return cls(pattern, include, recurse_dir)


def parse_exclude_pattern(pattern_str, fallback=FnmatchPattern):
    """Read pattern from string and return an instance of the appropriate implementation class."""
    epattern_obj = parse_pattern(pattern_str, include=False, fallback=fallback, recurse_dir=False)
    return CmdTuple(epattern_obj, IECommand.ExcludeNoRecurse)


def parse_inclexcl_command(cmd_line_str, fallback=ShellPattern):
    """Read a --patterns-from command from string and return a CmdTuple object."""

    cmd_prefix_map = {
        "-": IECommand.Exclude,
        "!": IECommand.ExcludeNoRecurse,
        "+": IECommand.Include,
        "R": IECommand.RootPath,
        "r": IECommand.RootPath,
        "P": IECommand.PatternStyle,
        "p": IECommand.PatternStyle,
    }
    if not cmd_line_str:
        raise ArgumentTypeError("A pattern/command must not be empty.")

    cmd = cmd_prefix_map.get(cmd_line_str[0])
    if cmd is None:
        raise ArgumentTypeError("A pattern/command must start with any of: %s" % ", ".join(cmd_prefix_map))

    # remaining text on command-line following the command character
    remainder_str = cmd_line_str[1:].lstrip()
    if not remainder_str:
        raise ArgumentTypeError("A pattern/command must have a value part.")

    if cmd is IECommand.RootPath:
        if not Path(remainder_str).is_absolute():
            warnings.warn(
                f"Root path {remainder_str!r} is not absolute, it is recommended to use an absolute path",
                UserWarning,
                stacklevel=2,
            )
        if not Path(remainder_str).exists():
            warnings.warn(f"Root path {remainder_str!r} does not exist", UserWarning, stacklevel=2)
        val = remainder_str
    elif cmd is IECommand.PatternStyle:
        # then remainder_str is something like 're' or 'sh'
        try:
            val = get_pattern_class(remainder_str)
        except ValueError:
            raise ArgumentTypeError(f"Invalid pattern style: {remainder_str}")
    else:
        # determine recurse_dir based on command type
        recurse_dir = command_recurses_dir(cmd)
        val = parse_pattern(remainder_str, cmd.is_include, fallback, recurse_dir)

    return CmdTuple(val, cmd)


def get_regex_from_pattern(pattern: str) -> str:
    """
    return a regular expression string corresponding to the given pattern string.

    the allowed pattern types are similar to the ones implemented by PatternBase subclasses,
    but here we rather do generic string matching, not specialised filesystem paths matching.
    """
    if len(pattern) > 2 and pattern[2] == ":" and pattern[:2] in {"sh", "re", "id"}:
        (style, pattern) = (pattern[:2], pattern[3:])
    else:
        (style, pattern) = ("id", pattern)  # "identical" match is the default
    if style == "sh":
        # (?ms) (meaning re.MULTILINE and re.DOTALL) are not desired here.
        regex = shellpattern.translate(pattern, match_end="").removeprefix("(?ms)")
    elif style == "re":
        regex = pattern
    elif style == "id":
        regex = re.escape(pattern)
    else:
        raise NotImplementedError
    return regex
