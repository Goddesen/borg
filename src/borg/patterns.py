import argparse
import fnmatch
from os.path import sep, normpath
import re
import sys
import unicodedata
from collections import namedtuple
from enum import Enum
from time import time_ns

from .helpers import clean_lines, shellpattern
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


class ArgparsePatternAction(argparse.Action):
    def __init__(self, nargs=1, **kw):
        super().__init__(nargs=nargs, **kw)

    def __call__(self, parser, args, values, option_string=None):
        parse_patternfile_line(values[0], args.paths, args.patterns, ShellPattern)


class ArgparsePatternFileAction(argparse.Action):
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
        load_pattern_file(fobj, args.paths, args.patterns)


class ArgparseExcludeFileAction(ArgparsePatternFileAction):
    def parse(self, fobj, args):
        load_exclude_file(fobj, args.patterns)


class PatternMatcher:
    """Represents a collection of pattern objects to match paths against.

    *fallback* is a boolean value that *match()* returns if no matching patterns are found.

    """

    def __init__(self, fallback=None):
        self._items = []

        # Value to return from match function when none of the patterns match.
        self.fallback = fallback

        # optimizations
        self._path_full_patterns = {}  # full path -> return value

        # indicates whether the last match() call ended on a pattern for which
        # we should recurse into any matching folder.  Will be set to True or
        # False when calling match().
        self.recurse_dir = None

        # whether to recurse into directories when no match is found
        # TODO: allow modification as a config option?
        self.recurse_dir_default = True

        self.include_patterns = []

        # TODO: move this info to parse_inclexcl_command and store in PatternBase subclass?
        self.is_include_cmd = {IECommand.Exclude: False, IECommand.ExcludeNoRecurse: False, IECommand.Include: True}

        # At least one pattern requires path to be unwrapped from surrounding separators
        self.patterns_require_unwrapped_path = False

        self.normalize_path_time_ns = 0
        self.fast_match_time_ns = 0
        self.slow_match_time_ns = 0

    def empty(self):
        return not len(self._items) and not len(self._path_full_patterns)

    def _add(self, pattern, cmd):
        """*cmd* is an IECommand value."""
        if isinstance(pattern, PathFullPattern):
            key = pattern.pattern  # full, normalized, wrapped path
            self._path_full_patterns[key] = cmd
        else:
            self._items.append((pattern, cmd))
            self.patterns_require_unwrapped_path |= pattern.pattern_requires_unwrapped_path

    def add(self, patterns, cmd):
        """Add list of patterns to internal list. *cmd* indicates whether the
        pattern is an include/exclude pattern, and whether recursion should be
        done on excluded folders.
        """
        for pattern in patterns:
            self._add(pattern, cmd)

    def add_includepaths(self, include_paths):
        """Used to add inclusion-paths from args.paths (from the command line)."""
        include_patterns = [parse_pattern(p, PathPrefixPattern) for p in include_paths]
        self.add(include_patterns, IECommand.Include)
        self.fallback = not include_patterns
        self.include_patterns = include_patterns

    def get_unmatched_include_patterns(self):
        """Note that this only returns patterns added via *add_includepaths*, and it
        won't return PathFullPattern patterns, as we do not maintain match_count for them.
        """
        return [p for p in self.include_patterns if p.match_count == 0 and not isinstance(p, PathFullPattern)]

    def add_inclexcl(self, patterns):
        """Add list of patterns (of type CmdTuple) to internal list."""
        for pattern, cmd in patterns:
            self._add(pattern, cmd)

    def match(self, path):
        """Return True or False depending on whether *path* is matched.

        If no match is found among the patterns in this matcher, then the value
        in self.fallback is returned (defaults to None).

        """
        t0 = time_ns()
        path = f"{normalize_path(path)}{sep}"
        if not path.startswith(sep):
            path = sep + path

        self.normalize_path_time_ns += time_ns() - t0
        t0 = time_ns()

        # do a fast lookup for full path matches (note: we do not count such matches):
        non_existent = object()
        value = self._path_full_patterns.get(path, non_existent)

        if value is not non_existent:
            # we have a full path match!
            self.fast_match_time_ns += time_ns() - t0
            self.recurse_dir = command_recurses_dir(value)
            return self.is_include_cmd[value]

        self.fast_match_time_ns += time_ns() - t0
        t0 = time_ns()

        # this is the slow way, if we have many patterns in self._items:
        unwrapped_path = ""
        if self.patterns_require_unwrapped_path:
            unwrapped_path = path.strip(sep)

        for pattern, cmd in self._items:
            if pattern.match(path, unwrapped_path, normalize=False):
                self.slow_match_time_ns += time_ns() - t0
                self.recurse_dir = pattern.recurse_dir
                return self.is_include_cmd[cmd]

        self.slow_match_time_ns += time_ns() - t0

        # by default we will recurse if there is no match
        self.recurse_dir = self.recurse_dir_default
        return self.fallback


def normalize_path(path):
    """normalize paths for MacOS (but do nothing on other platforms)"""
    # HFS+ converts paths to a canonical form, so users shouldn't be required to enter an exact match.
    # Windows and Unix filesystems allow different forms, so users always have to enter an exact match.
    return unicodedata.normalize("NFD", path) if sys.platform == "darwin" else path


class PatternBase:
    """Shared logic for inclusion/exclusion patterns."""

    PREFIX: str = None

    def __init__(self, pattern, recurse_dir=False):
        self.pattern_orig = pattern
        self.check_count = 0
        self.match_count = 0
        self.match_time_ns = 0
        pattern = normalize_path(pattern)
        self._prepare(pattern)
        self.recurse_dir = recurse_dir
        self.pattern_requires_unwrapped_path = False

    def match(self, path, unwrapped_path, normalize=True):
        """Return a boolean indicating whether *path* is matched by this pattern.

        If normalize is True (default), the path will get normalized using normalize_path(),
        otherwise it is assumed that it already is normalized using that function.
        """
        t0 = time_ns()
        if normalize:
            path = normalize_path(path)
            unwrapped_path = normalize_path(unwrapped_path)
        matches = self._match(path, unwrapped_path)
        self.match_time_ns += time_ns() - t0
        if matches:
            self.match_count += 1
        self.check_count += 1
        return matches

    def __repr__(self):
        return f"{type(self)}({self.pattern})"

    def __str__(self):
        return self.pattern_orig

    def _prepare(self, pattern):
        "Should set the value of self.pattern"
        raise NotImplementedError

    def _match(self, path, unwrapped_path):
        raise NotImplementedError


class PathFullPattern(PatternBase):
    """Full match of a path."""

    PREFIX = "pf"

    def _prepare(self, pattern):
        self.pattern = f"{sep}{normpath(pattern).strip(sep)}{sep}"

    def _match(self, path, _unwrapped_path):
        return path == self.pattern


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
        # sep at beginning is removed, even if it was the only character
        self.pattern = f"{sep}{normpath(pattern).strip(sep)}{sep}"
        if self.pattern == f"{sep}{sep}":
            self.pattern = sep

    def _match(self, path, _unwrapped_path):
        return path.startswith(self.pattern)


class FnmatchPattern(PatternBase):
    """Shell glob patterns to match.  A trailing slash means to
    match the contents of a directory, but not the directory itself.
    """

    PREFIX = "fm"
    DEFAULT_MATCH_START = rf"\A{sep}"

    def _prepare(self, pattern):
        match_start = self.DEFAULT_MATCH_START

        self.pattern = normpath(pattern).strip(sep)

        if re.match(rf"\*{sep}(?!\*)", self.pattern):
            self.pattern = self.pattern.removeprefix(rf"*{sep}")
            match_start = sep

        if pattern.endswith(sep):
            self.pattern += f"{sep}*"

        self.regex = re.compile(match_start + fnmatch.translate(self.pattern).rstrip(r"\Z") + sep)

    def _match(self, path, _unwrapped_path):
        return self.regex.search(path) is not None


class ShellPattern(PatternBase):
    """Shell glob patterns to match.  A trailing slash means to
    match the contents of a directory, but not the directory itself.
    """

    PREFIX = "sh"
    DEFAULT_MATCH_START = rf"\A{sep}"

    def _prepare(self, pattern):
        match_start = self.DEFAULT_MATCH_START

        self.pattern = normpath(pattern).lstrip(sep)

        if pattern.startswith(f"**{sep}"):
            # Optimization: Instead of matching many useless prefix groups for
            # "**/" start, instead just don't anchor the search. If the pattern
            # contains only literal characters this automatically collapses to
            # simple substring search with `re.search`.
            self.pattern = re.sub(rf"\A(?:\*\*{sep})+", "", self.pattern)
            match_start = sep

        if re.search(f"{sep}\*\*({sep})?$", pattern):
            # Optimization: Don't match useless suffix groups for "/**/" ending
            self.pattern = re.sub(rf"(?:{sep}\*\*)*{sep}\*\*{sep}?$", f"{sep}*", self.pattern)  # End is now just "/*"

        elif pattern.endswith(sep):
            # If pattern ends with "/", we match directory contents: ensure at
            # least one more path component matches
            self.pattern += sep + "*"

        self.regex = shellpattern.compile(self.pattern, match_start=match_start, match_end=sep)

    def _match(self, path, _unwrapped_path):
        return self.regex.search(path) is not None


class RegexPattern(PatternBase):
    """Regular expression to match."""

    PREFIX = "re"

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.pattern_requires_unwrapped_path = True

    def _prepare(self, pattern):
        self.pattern = pattern  # sep at beginning is NOT removed
        self.regex = re.compile(pattern)

    def _match(self, _path, unwrapped_path):
        # Normalize path separators
        if sep != "/":
            unwrapped_path = unwrapped_path.replace(sep, "/")

        return self.regex.search(unwrapped_path) is not None


_PATTERN_CLASSES = {FnmatchPattern, PathFullPattern, PathPrefixPattern, RegexPattern, ShellPattern}

_PATTERN_CLASS_BY_PREFIX = {i.PREFIX: i for i in _PATTERN_CLASSES}

CmdTuple = namedtuple("CmdTuple", "val cmd")


class IECommand(Enum):
    """A command that an InclExcl file line can represent."""

    RootPath = 1
    PatternStyle = 2
    Include = 3
    Exclude = 4
    ExcludeNoRecurse = 5


def command_recurses_dir(cmd):
    # TODO?: raise error or return None if *cmd* is RootPath or PatternStyle
    return cmd not in [IECommand.ExcludeNoRecurse]


def get_pattern_class(prefix):
    try:
        return _PATTERN_CLASS_BY_PREFIX[prefix]
    except KeyError:
        raise ValueError(f"Unknown pattern style: {prefix}") from None


def parse_pattern(pattern, fallback=FnmatchPattern, recurse_dir=True):
    """Read pattern from string and return an instance of the appropriate implementation class."""
    if len(pattern) > 2 and pattern[2] == ":" and pattern[:2].isalnum():
        (style, pattern) = (pattern[:2], pattern[3:])
        cls = get_pattern_class(style)
    else:
        cls = fallback
    return cls(pattern, recurse_dir)


def parse_exclude_pattern(pattern_str, fallback=FnmatchPattern):
    """Read pattern from string and return an instance of the appropriate implementation class."""
    epattern_obj = parse_pattern(pattern_str, fallback, recurse_dir=False)
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
        raise argparse.ArgumentTypeError("A pattern/command must not be empty.")

    cmd = cmd_prefix_map.get(cmd_line_str[0])
    if cmd is None:
        raise argparse.ArgumentTypeError("A pattern/command must start with any of: %s" % ", ".join(cmd_prefix_map))

    # remaining text on command-line following the command character
    remainder_str = cmd_line_str[1:].lstrip()
    if not remainder_str:
        raise argparse.ArgumentTypeError("A pattern/command must have a value part.")

    if cmd is IECommand.RootPath:
        # TODO: validate string?
        val = remainder_str
    elif cmd is IECommand.PatternStyle:
        # then remainder_str is something like 're' or 'sh'
        try:
            val = get_pattern_class(remainder_str)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid pattern style: {remainder_str}")
    else:
        # determine recurse_dir based on command type
        recurse_dir = command_recurses_dir(cmd)
        val = parse_pattern(remainder_str, fallback, recurse_dir)

    return CmdTuple(val, cmd)


def get_regex_from_pattern(pattern: str, match_end: str = "", flags: re.RegexFlag = re.NOFLAG) -> str:
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
        regex = shellpattern.compile(pattern, match_end=match_end, flags=flags)
    elif style == "re":
        regex = re.compile(pattern + match_end)
    elif style == "id":
        regex = re.compile(re.escape(pattern) + match_end)
    else:
        raise NotImplementedError

    return regex
