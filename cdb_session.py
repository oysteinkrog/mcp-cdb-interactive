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


class CDBError(Exception):
    pass


def _validate_path(path: str, label: str = "path") -> None:
    """Reject paths containing characters that could cause CDB command injection."""
    bad = _UNSAFE_PATH_CHARS.intersection(path)
    if bad:
        chars = ", ".join(repr(c) for c in sorted(bad))
        raise CDBError(f"Invalid {label}: contains unsafe characters {chars}")


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
        timeout: int = 30,
        verbose: bool = False,
    ):
        self.session_id = str(uuid.uuid4())
        self.cdb_path = cdb_path
        self.timeout = timeout
        self.verbose = verbose
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
            if self._state != "exited":
                self._state = "broken"
            self._output_lines.clear()

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
            timeout=timeout,
            verbose=verbose,
        )
        session._target_pid = pid
        return session
