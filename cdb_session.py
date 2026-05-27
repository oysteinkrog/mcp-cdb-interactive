"""Interactive CDB debugging session manager.

Manages a CDB subprocess with stdin/stdout pipes, background output reader,
and command-marker synchronization for reliable command/response pairing.
"""

import subprocess
import threading
import time
import re
import os
import shutil
import sys
import uuid
import ctypes
import logging
import shlex
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)

COMMAND_MARKER = "<<<CMD_DONE_{id}>>>"
COMMAND_MARKER_RE = re.compile(r"<<<CMD_DONE_([a-f0-9-]+)>>>")

# Matches CDB/WinDbg prompts: "0:000>", "0:000:x86>", "kd>", etc.
PROMPT_RE = re.compile(r"^(\d+:\d+(?::\w+)?|kd)>\s?")

EXIT_PATTERNS = [
    re.compile(r"quit:"),
    re.compile(r"ntdll!NtTerminateProcess"),
    re.compile(r"Process exited"),
]

# Pattern to extract debuggee PID from `|` command output.
# Example: ".  0	id: 1a2b	create	name: ping.exe"
DEBUGGEE_PID_RE = re.compile(r"id:\s+([0-9a-f]+)", re.IGNORECASE)

DEFAULT_CDB_PATHS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe"),
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
]

DEFAULT_EXCEPTION_HANDLERS = [
    "sxe av",   # Access violation
    "sxe sov",  # Stack overflow
    "sxe eh",   # C++ exception
    "sxe clr",  # CLR exception
]

# Maximum output lines to buffer when debuggee is running (prevents unbounded memory growth)
MAX_OUTPUT_BUFFER_SIZE = 10000

# Allowlist for exception handler commands (sxe/sxd/sxn/sxi + exception code)
_EXCEPTION_HANDLER_RE = re.compile(r"^\s*sx[edni]\s+\w+$")

# Allowlist for resume commands passed to cdb_go
ALLOWED_RESUME_COMMANDS = re.compile(
    r"^\s*("
    r"g|gu|gc|gn|gN|gh|gH"       # go variants
    r"|p|pa|pc|pt|pct"            # step over variants
    r"|t|ta|tc|tt|tct"            # step into variants
    r"|wt"                        # trace and watch
    r")(\s+\S+)?\s*$"            # optional address argument
)


# Characters not allowed in paths passed to CDB commands (prevent injection)
_UNSAFE_PATH_CHARS = set('";\r\n')

# Dangerous CDB commands that can execute arbitrary OS commands or load code.
# Blocked by default to prevent prompt-injection-driven code execution.
DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"^\s*\.shell\b", re.IGNORECASE),       # OS command execution
    re.compile(r"^\s*\.script\w*\b", re.IGNORECASE),   # Script loading/execution
    re.compile(r"^\s*\.load\b", re.IGNORECASE),        # Extension DLL loading
    re.compile(r"^\s*\.loadby\b", re.IGNORECASE),      # Extension DLL loading
    re.compile(r"^\s*!for_each_\w+", re.IGNORECASE),   # Iteration with command execution
    re.compile(r"^\s*!shell\b", re.IGNORECASE),        # Shell extension alias
    re.compile(r"^\s*\.writemem\b", re.IGNORECASE),    # Write memory to file
    re.compile(r"^\s*\.create\b", re.IGNORECASE),      # Create process
    re.compile(r"^\s*\.cordll\b", re.IGNORECASE),      # Loads CLR DAC DLL
    re.compile(r"^\s*\.net\b", re.IGNORECASE),         # Loads managed debugging extension
    re.compile(r"^\s*\.dvalloc\b", re.IGNORECASE),     # Allocate virtual memory in debuggee
    re.compile(r"^\s*\.dvfree\b", re.IGNORECASE),      # Free virtual memory in debuggee
    # Scripting / control-flow commands with brace-delimited bodies. The
    # splitter on [;\r\n] does not see inside { ... } blocks, so without
    # these patterns `.if (1) { .shell whoami }` (and all siblings)
    # would bypass the .shell block.
    re.compile(r"^\s*\.foreach\b", re.IGNORECASE),
    re.compile(r"^\s*\.do\b", re.IGNORECASE),
    re.compile(r"^\s*\.while\b", re.IGNORECASE),
    re.compile(r"^\s*\.if\b", re.IGNORECASE),
    re.compile(r"^\s*\.elsif\b", re.IGNORECASE),
    re.compile(r"^\s*\.else\b", re.IGNORECASE),
    re.compile(r"^\s*\.for\b", re.IGNORECASE),
    re.compile(r"^\s*\.block\b", re.IGNORECASE),
    re.compile(r"^\s*\.catch\b", re.IGNORECASE),
    re.compile(r"^\s*\.continue\b", re.IGNORECASE),
    re.compile(r"^\s*\.break\b", re.IGNORECASE),
    # Command-file include forms — read and execute commands from a file.
    re.compile(r"^\s*\$\$?>?<", re.IGNORECASE),        # $<, $$<, $><, $$><
]

# Split commands on semicolons and newlines (prevents newline-based bypass).
_CMD_SEPARATOR_RE = re.compile(r"[;\r\n]+")


def is_dangerous_command(command: str, allow_dangerous: bool = False) -> Optional[str]:
    """Check if a command matches dangerous patterns.

    Returns the matched pattern source if dangerous, None if safe.
    """
    if allow_dangerous:
        return None
    for subcmd in _CMD_SEPARATOR_RE.split(command):
        subcmd = subcmd.strip()
        if not subcmd:
            continue
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if pattern.match(subcmd):
                return pattern.pattern
    return None


class CDBError(Exception):
    pass


class CDBValidationError(CDBError):
    """Raised by path/parameter validators.

    The MCP server maps this to INVALID_PARAMS, distinct from operational
    CDBError (process spawn failure, command timeout, etc.) which maps to
    INTERNAL_ERROR.
    """


def _validate_path(path: str, label: str = "path") -> None:
    """Reject paths containing characters that could cause CDB command injection."""
    bad = _UNSAFE_PATH_CHARS.intersection(path)
    if bad:
        chars = ", ".join(repr(c) for c in sorted(bad))
        raise CDBValidationError(f"Invalid {label}: contains unsafe characters {chars}")


def _has_unc_prefix(path: str) -> bool:
    """True if path is a UNC path under either separator convention.

    Windows accepts `//server/share` in many contexts as a synonym for
    `\\\\server\\share`, so check both forms before any filesystem call.
    """
    normalised = path.replace("/", "\\")
    return normalised.startswith("\\\\")


# Kernel-mode dump magic bytes at file offset 0 (cdb.exe cannot open these)
KERNEL_DUMP_MAGICS = (b"PAGEDU64", b"PAGEDUMP")

# Dump suffixes cdb.exe will accept
_DUMP_SUFFIXES = (".dmp", ".mdmp", ".hdmp")


def _validate_dump_path(path: str) -> None:
    """Validate a user-mode dump file path before passing to cdb -z.

    Reuses _validate_path for injection safety, then layers dump-specific checks:
    suffix allowlist, leading-dash rejection (would parse as a CDB flag), Windows
    trailing-backslash parity (list2cmdline quoting quirk), existence, and a
    magic-byte sniff that rejects kernel-mode dumps (which cdb cannot open).
    """
    _validate_path(path, "dump path")
    if path.startswith("-"):
        raise CDBValidationError("Invalid dump path: cannot start with '-'")
    if _has_unc_prefix(path):
        raise CDBValidationError(
            "UNC paths are not allowed for dump files. Copy the dump locally "
            "or map the share to a drive letter."
        )
    m = re.search(r"\\+$", path)
    if m and len(m.group()) % 2 == 1:
        raise CDBValidationError("Invalid dump path: odd number of trailing backslashes")
    if not path.lower().endswith(_DUMP_SUFFIXES):
        raise CDBValidationError(
            f"Unsupported dump file extension: {path!r}. "
            f"Expected one of {_DUMP_SUFFIXES}."
        )
    if not os.path.isfile(path):
        raise CDBValidationError(f"Dump file not found: {path}")
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError as e:
        raise CDBValidationError(f"Cannot read dump header: {e}")
    if head in KERNEL_DUMP_MAGICS:
        raise CDBValidationError(
            f"Kernel-mode dump detected (magic {head!r}). "
            f"cdb.exe only handles user-mode dumps; use kd.exe or windbg.exe."
        )


_SYMPATH_URL_RE = re.compile(r"^https?://[\w./-]+$", re.IGNORECASE)
_SYMPATH_SRV_RE = re.compile(
    r"^(SRV|SYMSRV|CACHE)\*[^*]*(\*[^*]*)*$",
    re.IGNORECASE,
)


def _validate_sympath(sympath: str) -> None:
    """Validate a symbol path passed via -y.

    Symbol paths legitimately contain ';' (component separator), '*' (SRV tokens),
    and URLs. _validate_path is too strict here. Splits on ';' and applies
    per-component rules.
    """
    if len(sympath) > 2048:
        raise CDBValidationError("Symbol path too long (max 2048 chars)")
    for raw in sympath.split(";"):
        component = raw.strip()
        if not component:
            continue
        if any(c in component for c in '"\r\n'):
            raise CDBValidationError(f"Invalid symbol-path component: {component!r}")
        # URL inside a component: validate strictly. Strip leading SRV*..*  prefix.
        url_part = component
        if "*" in component:
            head, _, tail = component.rpartition("*")
            url_part = tail
            if not _SYMPATH_SRV_RE.match(component) and "://" not in tail:
                raise CDBValidationError(f"Invalid SRV component: {component!r}")
        if "://" in url_part:
            if not _SYMPATH_URL_RE.match(url_part):
                raise CDBValidationError(
                    f"Invalid symbol-server URL: {url_part!r} "
                    f"(no credentials, query strings, or fragments allowed)"
                )


def _validate_search_path(path: str) -> None:
    """Validate a multi-directory search path (e.g. for -i image path).

    Allows ';' as component separator. Rejects unsafe chars per component and
    UNC paths (\\\\server\\share) to prevent unintended network traversal.
    """
    if len(path) > 2048:
        raise CDBValidationError("Search path too long (max 2048 chars)")
    for raw in path.split(";"):
        component = raw.strip()
        if not component:
            continue
        if any(c in component for c in '"\r\n'):
            raise CDBValidationError(f"Invalid search-path component: {component!r}")
        if _has_unc_prefix(component):
            raise CDBValidationError(
                f"UNC paths not allowed in search path: {component!r}"
            )


def _find_cdb(custom_path: Optional[str] = None) -> str:
    if custom_path:
        expanded = os.path.expandvars(os.path.expanduser(custom_path))
        if os.path.isfile(expanded):
            return expanded
    # Try PATH lookup
    for name in ("cdb.exe", "cdbX64.exe"):
        found = shutil.which(name)
        if found:
            return found
    # Try well-known locations
    for p in DEFAULT_CDB_PATHS:
        if os.path.isfile(p):
            return p
    raise CDBError(
        "cdb.exe not found. Install Windows SDK or WinDbg Preview, "
        "or pass --cdb-path."
    )


class CDBSession:
    """Manages a single interactive CDB subprocess."""

    def __init__(
        self,
        cdb_path: str,
        args: list[str],
        *,
        session_kind: str,
        timeout: int = 30,
        verbose: bool = False,
    ):
        if session_kind not in ("live-launch", "live-attach", "dump"):
            raise CDBValidationError(f"Invalid session_kind: {session_kind!r}")
        self.session_id = str(uuid.uuid4())
        self.cdb_path = cdb_path
        self.timeout = timeout
        self.verbose = verbose
        self.session_kind = session_kind
        self.dump_path: Optional[str] = None
        self._state = "starting"
        self._target_pid: Optional[int] = None

        self._output_lines: deque[str] = deque(maxlen=MAX_OUTPUT_BUFFER_SIZE)
        self._unsolicited_lines: list[str] = []  # Output captured between commands
        self._output_truncated = False  # Set when deque overflow drops lines
        self._lock = threading.Lock()
        self._cmd_lock = threading.Lock()  # Serialize all stdin/protocol operations
        self._cmd_event = threading.Event()
        self._marker_observed = False  # True if marker was seen (vs event set by finally)
        self._pending_marker_id: Optional[str] = None
        self._reader: Optional[threading.Thread] = None

        cmd = [self.cdb_path] + args
        if self.verbose:
            logger.info("CDB command: %s", " ".join(cmd))

        try:
            # CREATE_NEW_CONSOLE gives CDB and its child a real console
            # window so .NET Console APIs work (e.g. Console.WindowWidth).
            # Piped stdin/stdout still work for our marker protocol.
            creationflags = subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
        except Exception as e:
            raise CDBError(f"Failed to start CDB: {e}")

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        try:
            self._wait_initial_prompt()
            self._resolve_debuggee_pid()
        except Exception:
            self.close()
            raise

    @property
    def state(self) -> str:
        if self._process is not None and self._process.poll() is not None:
            with self._lock:
                self._state = "exited"
        return self._state

    @property
    def pid(self) -> Optional[int]:
        return self._target_pid

    def _read_loop(self):
        """Background thread: reads CDB stdout line-by-line."""
        try:
            proc = self._process
            if proc is None or proc.stdout is None:
                return
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n\r")
                if self.verbose:
                    print(f"CDB> {line}", file=sys.stderr)

                # Parse outside lock to reduce contention
                marker_match = COMMAND_MARKER_RE.search(line)
                is_prompt = PROMPT_RE.match(line) is not None
                is_exit = any(pat.search(line) for pat in EXIT_PATTERNS)

                with self._lock:
                    if marker_match:
                        marker_id = marker_match.group(1)
                        if (self._pending_marker_id
                                and marker_id == self._pending_marker_id):
                            self._marker_observed = True
                            self._cmd_event.set()
                        continue

                    # Track deque overflow (oldest lines dropped)
                    if len(self._output_lines) == MAX_OUTPUT_BUFFER_SIZE:
                        self._output_truncated = True
                    self._output_lines.append(line)

                    # Also collect unsolicited output (between commands)
                    if self._pending_marker_id is None:
                        self._unsolicited_lines.append(line)

                    # State detection: exited is terminal, never flip back
                    if self._state != "exited":
                        if is_exit:
                            self._state = "exited"
                        elif is_prompt:
                            self._state = "broken"
        except (IOError, ValueError, UnicodeDecodeError):
            pass
        finally:
            with self._lock:
                self._state = "exited"
            self._cmd_event.set()

    def _wait_initial_prompt(self):
        """Wait for CDB to be ready after launch."""
        init_id = str(uuid.uuid4())
        self._cmd_event.clear()
        with self._lock:
            self._marker_observed = False
            self._pending_marker_id = init_id
            self._output_lines.clear()

        try:
            self._process.stdin.write(
                f".echo {COMMAND_MARKER.format(id=init_id)}\n"
            )
            self._process.stdin.flush()
        except IOError as e:
            raise CDBError(f"Failed to communicate with CDB: {e}")

        if not self._cmd_event.wait(timeout=self.timeout):
            raise CDBError("CDB initialization timed out")

        with self._lock:
            marker_was_seen = self._marker_observed
            self._pending_marker_id = None
            tail = list(self._output_lines)[-30:]
            if self._state != "exited":
                self._state = "broken"
            self._output_lines.clear()

        # The reader thread's finally clause also sets the event, so a
        # set event does not by itself mean the marker arrived. Without
        # this check, a CDB that died on startup (corrupt dump, missing
        # binary, etc.) would return a session that looks "broken" but
        # is actually exited — same fix as send_command() at the bottom.
        if not marker_was_seen:
            tail_text = "\n".join(tail) if tail else "(no output)"
            raise CDBError(
                "CDB exited before producing the initial prompt. "
                f"Last output:\n{tail_text}"
            )

    def _resolve_debuggee_pid(self):
        """Detect the debuggee's PID using the | command."""
        if self._target_pid is not None:
            return
        if self.state == "exited":
            return

        try:
            output = self.send_command("|")
            match = DEBUGGEE_PID_RE.search(output)
            if match:
                self._target_pid = int(match.group(1), 16)
                if self.verbose:
                    logger.info(
                        "Debuggee PID: %d (0x%x)",
                        self._target_pid, self._target_pid,
                    )
        except CDBError:
            pass

    def send_command(self, command: str, timeout: Optional[int] = None) -> str:
        """Send a command to CDB and return the output text.

        The debuggee must be in a broken state. For resume commands
        (g, gu, etc.) use resume() instead.

        Args:
            command: WinDbg/CDB command string.
            timeout: Override default timeout for this command.

        Returns:
            Output text from CDB (may be multi-line).
        """
        # Serialize all stdin/protocol operations
        with self._cmd_lock:
            if self._process is None or self._process.poll() is not None:
                raise CDBError("CDB process has exited")

            with self._lock:
                if self._state == "running":
                    raise CDBError(
                        "Debuggee is running. Use cdb_break to interrupt first, "
                        "or cdb_go for execution control commands."
                    )

            marker_id = str(uuid.uuid4())
            marker = COMMAND_MARKER.format(id=marker_id)

            self._cmd_event.clear()
            with self._lock:
                self._marker_observed = False
                self._pending_marker_id = marker_id
                # Snapshot unsolicited output before clearing
                unsolicited = list(self._unsolicited_lines)
                self._unsolicited_lines.clear()
                self._output_lines.clear()
                self._output_truncated = False

            try:
                self._process.stdin.write(f"{command}\n.echo {marker}\n")
                self._process.stdin.flush()
            except IOError as e:
                raise CDBError(f"Failed to send command: {e}")

            cmd_timeout = timeout or self.timeout
            if not self._cmd_event.wait(timeout=cmd_timeout):
                raise CDBError(
                    f"Command timed out after {cmd_timeout}s: {command}"
                )

            with self._lock:
                marker_was_seen = self._marker_observed
                was_truncated = self._output_truncated
                result = list(self._output_lines)
                self._output_lines.clear()
                self._output_truncated = False
                self._pending_marker_id = None

            # If event was set but marker wasn't seen, CDB died
            if not marker_was_seen:
                raise CDBError("CDB process exited during command execution")

        cleaned = []
        if was_truncated:
            cleaned.append("[output truncated - oldest lines dropped]")
        for line in result:
            if PROMPT_RE.match(line):
                rest = PROMPT_RE.sub("", line).strip()
                if rest:
                    cleaned.append(rest)
            else:
                cleaned.append(line)

        output = "\n".join(cleaned)

        # Prepend unsolicited output if any (stop-reason, exceptions, etc.)
        if unsolicited:
            unsolicited_text = "\n".join(unsolicited)
            if output:
                output = f"[unsolicited output]\n{unsolicited_text}\n\n[command output]\n{output}"
            else:
                output = f"[unsolicited output]\n{unsolicited_text}"

        return output

    def resume(self, command: str = "g") -> None:
        """Send a resume command without waiting for completion.

        Transitions the session to 'running' state. Use send_break()
        to interrupt execution later.

        Args:
            command: Resume command (g, gu, p, t, etc.).
        """
        with self._cmd_lock:
            if self._process is None or self._process.poll() is not None:
                raise CDBError("CDB process has exited")

            try:
                self._process.stdin.write(f"{command}\n")
                self._process.stdin.flush()
            except IOError as e:
                raise CDBError(f"Failed to send resume command: {e}")

            with self._lock:
                self._state = "running"
                self._unsolicited_lines.clear()

    def send_break(self) -> bool:
        """Send break signal to interrupt a running debuggee.

        Uses DebugBreakProcess on the debuggee PID for reliability,
        with Ctrl+C fallback. Does not change state - the reader thread
        will detect the prompt when the debuggee actually stops.
        """
        with self._cmd_lock:
            if self._process is None or self._process.poll() is not None:
                return False

            target_pid = self._target_pid
            if target_pid:
                try:
                    kernel32 = ctypes.windll.kernel32
                    PROCESS_CREATE_THREAD = 0x0002
                    handle = kernel32.OpenProcess(
                        PROCESS_CREATE_THREAD, False, target_pid,
                    )
                    if handle:
                        try:
                            result = kernel32.DebugBreakProcess(handle)
                            if result:
                                return True
                        finally:
                            kernel32.CloseHandle(handle)
                except Exception as e:
                    logger.warning("DebugBreakProcess on debuggee failed: %s", e)

            # Fallback: send Ctrl+C to CDB stdin
            try:
                self._process.stdin.write("\x03")
                self._process.stdin.flush()
                return True
            except IOError:
                return False

    def get_output(self, max_lines: int = 200) -> str:
        """Return buffered output without clearing it.

        Useful for reading unsolicited output while the debuggee is running.

        Args:
            max_lines: Maximum number of recent lines to return.

        Returns:
            Recent buffered output text.
        """
        with self._lock:
            lines = list(self._output_lines)[-max_lines:]
            truncated = self._output_truncated
        prefix = "[output truncated - oldest lines dropped]\n" if truncated else ""
        return prefix + "\n".join(lines)

    def wait_for_state_change(
        self, target_states: tuple[str, ...] = ("broken", "exited"),
        timeout: Optional[int] = None,
    ) -> str:
        """Wait until session enters one of the target states.

        Args:
            target_states: States to wait for.
            timeout: Timeout in seconds (None = use default).

        Returns:
            The state that was entered.
        """
        wait_timeout = timeout or self.timeout
        end_time = time.monotonic() + wait_timeout
        while time.monotonic() < end_time:
            current = self.state
            if current in target_states:
                return current
            time.sleep(0.1)

        return self.state

    def create_dump(self, path: str) -> str:
        """Create a minidump of the debuggee.

        Args:
            path: File path for the dump file.

        Returns:
            Output from the dump command.
        """
        _validate_path(path, "dump path")
        return self.send_command(f'.dump /ma /o "{path}"')

    def detach(self):
        """Detach from the debuggee without killing it."""
        with self._cmd_lock:
            if self._process is None or self._process.poll() is not None:
                return

            try:
                self._process.stdin.write(".detach\n")
                self._process.stdin.flush()
            except IOError:
                pass

            try:
                self._process.stdin.write("q\n")
                self._process.stdin.flush()
                self._process.wait(timeout=5)
            except Exception:
                pass

        self._cleanup()

    def close(self):
        """Quit CDB, killing the debuggee if still running."""
        if self._process is None:
            return
        if self._process.poll() is not None:
            self._cleanup()
            return

        with self._cmd_lock:
            try:
                self._process.stdin.write("q\n")
                self._process.stdin.flush()
                self._process.wait(timeout=5)
            except Exception:
                pass

        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except Exception:
                self._process.kill()

        self._cleanup()

    def _cleanup(self):
        with self._lock:
            self._state = "exited"

        # Close pipes first to unblock reader thread
        proc = self._process
        if proc is not None:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass

        # Join reader thread with timeout
        reader = self._reader
        if reader is not None and reader.is_alive():
            reader.join(timeout=2.0)

        self._process = None
        self._reader = None

    @classmethod
    def launch(
        cls,
        executable: str,
        arguments: str = "",
        cdb_path: str = "",
        exception_handlers: Optional[list[str]] = None,
        timeout: int = 30,
        verbose: bool = False,
    ) -> "CDBSession":
        """Launch a process under CDB.

        Breaks at the initial loader breakpoint so the caller has
        interactive control. Use resume() to continue execution.

        Args:
            executable: Path to the executable to debug.
            arguments: Command-line arguments for the target process.
            cdb_path: Path to cdb.exe (auto-detected if not provided).
            exception_handlers: List of sxe commands. Defaults to common handlers.
            timeout: Command timeout in seconds.
            verbose: Enable verbose logging.
        """
        resolved_cdb = _find_cdb(cdb_path) if cdb_path else _find_cdb()

        exc_handlers = exception_handlers or DEFAULT_EXCEPTION_HANDLERS
        for handler in exc_handlers:
            if not _EXCEPTION_HANDLER_RE.match(handler):
                raise CDBError(
                    f"Invalid exception handler: {handler!r}. "
                    f"Only sx[edni] commands are allowed (e.g. 'sxe av')."
                )
        init_cmds = "; ".join(exc_handlers)

        # -G: ignore final breakpoint (process exit), initial breakpoint still fires
        # -o: debug child processes
        args = ["-G", "-o"]
        if init_cmds:
            args.extend(["-c", init_cmds])

        args.append(executable)
        if arguments:
            # Use shlex.split to properly handle quoted arguments
            # posix=False preserves Windows-style quoting
            args.extend(shlex.split(arguments, posix=False))

        session = cls(
            cdb_path=resolved_cdb,
            args=args,
            session_kind="live-launch",
            timeout=timeout,
            verbose=verbose,
        )
        return session

    @classmethod
    def attach(
        cls,
        pid: int,
        invasive: bool = True,
        cdb_path: str = "",
        timeout: int = 30,
        verbose: bool = False,
    ) -> "CDBSession":
        """Attach CDB to a running process.

        Args:
            pid: Process ID to attach to.
            invasive: If True, attach invasively (-p). If False, non-invasive (-pv).
            cdb_path: Path to cdb.exe (auto-detected if not provided).
            timeout: Command timeout in seconds.
            verbose: Enable verbose logging.
        """
        resolved_cdb = _find_cdb(cdb_path) if cdb_path else _find_cdb()

        if invasive:
            args = ["-p", str(pid)]
        else:
            args = ["-pv", "-p", str(pid)]

        session = cls(
            cdb_path=resolved_cdb,
            args=args,
            session_kind="live-attach",
            timeout=timeout,
            verbose=verbose,
        )
        session._target_pid = pid
        return session

    @classmethod
    def open_dump(
        cls,
        dump_path: str,
        cdb_path: str = "",
        symbol_path: Optional[str] = None,
        image_path: Optional[str] = None,
        timeout: int = 300,
        verbose: bool = False,
    ) -> "CDBSession":
        """Open a user-mode crash dump for postmortem analysis.

        Args:
            dump_path: Path to a user-mode .dmp/.mdmp/.hdmp file.
            cdb_path: Path to cdb.exe (auto-detected if not provided).
            symbol_path: Optional symbol search path (-y). Replaces
                _NT_SYMBOL_PATH for this session; include the env value
                in the string to keep it.
            image_path: Optional executable image search path (-i).
            timeout: Initialisation timeout in seconds. Default 300s to allow
                cold-cache symbol downloads from msdl on first run.
            verbose: Enable verbose logging.

        Raises:
            CDBError: if validation fails (bad path, kernel dump, missing file,
                injection-unsafe path, etc).
        """
        _validate_dump_path(dump_path)
        if symbol_path is not None:
            _validate_sympath(symbol_path)
        if image_path is not None:
            _validate_search_path(image_path)

        resolved_cdb = _find_cdb(cdb_path) if cdb_path else _find_cdb()

        # NB: -G (ignore final breakpoint) and -o (debug child processes) are
        # live-process flags and must NOT be passed in dump mode.
        args: list[str] = []
        if symbol_path:
            args.extend(["-y", symbol_path])
        if image_path:
            args.extend(["-i", image_path])
        args.extend(["-z", dump_path])

        session = cls(
            cdb_path=resolved_cdb,
            args=args,
            session_kind="dump",
            timeout=timeout,
            verbose=verbose,
        )
        session.dump_path = dump_path
        return session
