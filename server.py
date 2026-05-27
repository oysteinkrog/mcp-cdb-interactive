"""MCP server for interactive CDB debugging sessions.

Provides tools to launch processes under CDB, attach to running processes,
send debugger commands, break into execution, create dumps, and detach.
"""

import argparse
import asyncio
import atexit
import logging
import sys
from typing import Literal, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)
from pydantic import BaseModel, Field

from cdb_session import (
    CDBSession,
    CDBError,
    _find_cdb,
    ALLOWED_RESUME_COMMANDS,
    is_dangerous_command,
)

logger = logging.getLogger(__name__)

# Single active session (one debugger at a time)
_session: Optional[CDBSession] = None


def _get_session() -> CDBSession:
    if _session is None:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="No active debugging session. Use cdb_launch, cdb_attach, or cdb_open_dump first."
        ))
    return _session


def _require_live_session(session: CDBSession, tool_name: str) -> None:
    """Block tools that require a live debuggee from operating on dump sessions."""
    if session.session_kind == "dump":
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=(
                f"{tool_name} is not available for dump sessions — the dump is "
                f"a static snapshot. Use cdb_cmd for read-only analysis."
            ),
        ))


def _clear_session():
    global _session
    if _session is not None:
        try:
            _session.close()
        except Exception:
            pass
        _session = None


# --- Pydantic models for tool parameters ---

class CdbLaunchParams(BaseModel):
    """Launch a process under the CDB debugger."""
    executable: str = Field(
        description="Path to the executable to launch (e.g., 'dotnet.exe')"
    )
    arguments: str = Field(
        default="",
        description="Command-line arguments for the target process"
    )
    exception_handlers: Optional[list[str]] = Field(
        default=None,
        description=(
            "CDB exception handler commands (e.g., ['sxe av', 'sxe clr']). "
            "Defaults to common handlers for AV, stack overflow, C++ and CLR exceptions."
        )
    )
    timeout: Optional[int] = Field(
        default=None,
        description="Override default command timeout in seconds"
    )


class CdbAttachParams(BaseModel):
    """Attach CDB to a running process."""
    pid: int = Field(description="Process ID to attach to")
    invasive: bool = Field(
        default=True,
        description="If true, attach invasively (-p). If false, non-invasive (-pv)."
    )
    timeout: Optional[int] = Field(
        default=None,
        description="Override default command timeout in seconds"
    )


class CdbCmdParams(BaseModel):
    """Execute WinDbg/CDB commands in the active session."""
    command: str = Field(
        description=(
            "WinDbg command(s) to execute. Multiple commands can be "
            "separated by semicolons."
        )
    )
    timeout: Optional[int] = Field(
        default=None,
        description="Override default command timeout in seconds"
    )


class CdbGoParams(BaseModel):
    """Resume execution in the debugger."""
    command: str = Field(
        default="g",
        description=(
            "Debugger resume command. Common: 'g' (go/continue), "
            "'g <addr>' (go to address), 'gu' (go up/step out). "
            "For single-step commands (p, t) that return to the prompt "
            "immediately, use cdb_cmd instead."
        )
    )


class CdbDumpParams(BaseModel):
    """Create a minidump of the debuggee."""
    path: str = Field(
        description="File path where the dump will be saved (e.g., 'C:\\\\temp\\\\crash.dmp')"
    )


class CdbOpenDumpParams(BaseModel):
    """Open a Windows user-mode crash dump for postmortem analysis."""
    dump_path: str = Field(
        description=(
            "Absolute path to a Windows user-mode crash dump (.dmp, .mdmp, .hdmp). "
            "For postmortem analysis only — use cdb_launch for new processes or "
            "cdb_attach for live processes. Kernel dumps are pre-rejected; "
            "use kd.exe or windbg.exe for those."
        )
    )
    symbol_path: Optional[str] = Field(
        default=None,
        description=(
            "Symbol path override (-y). REPLACES _NT_SYMBOL_PATH for this "
            "session — to combine local PDBs with the public symbol server, "
            "supply the full combined path, e.g.: "
            "'C:\\\\MyPdbs;SRV*C:\\\\Symbols*https://msdl.microsoft.com/download/symbols'. "
            "Leave unset to use the server's _NT_SYMBOL_PATH environment variable."
        )
    )
    image_path: Optional[str] = Field(
        default=None,
        description=(
            "Executable image search path (-i). Use when binaries moved since "
            "the dump was captured. Semicolon-separated for multiple directories."
        )
    )
    auto_triage: bool = Field(
        default=True,
        description=(
            "Run the canonical triage sweep on open (.lastevent, !analyze -v, "
            "kn, ~*kn, lm). Set false to open without auto-analysis."
        )
    )
    timeout: Optional[int] = Field(
        default=300,
        description=(
            "Timeout in seconds for the initial sweep. Default 300s "
            "accommodates cold-cache symbol fetches from msdl on first run."
        )
    )


class CdbOutputParams(BaseModel):
    """Read buffered debugger output."""
    max_lines: int = Field(
        default=200,
        description="Maximum number of recent lines to return"
    )


class CdbWaitParams(BaseModel):
    """Wait for debuggee state change."""
    timeout: Optional[int] = Field(
        default=None,
        description="Timeout in seconds (default: server timeout)"
    )


# Extensions ship with the debugger and load by name (no path argument from
# the LLM, so path injection is structurally impossible).
_MANAGED_EXTENSIONS = ("sos", "sosex", "mex", "psscor4", "netext")
_BUILTIN_EXTENSIONS = ("wow64exts", "exts")


class CdbLoadExtensionParams(BaseModel):
    """Load a debugger extension from an allowlist."""
    name: Literal[
        "sos", "sosex", "mex", "psscor4", "netext", "wow64exts", "exts"
    ] = Field(
        description=(
            "Extension to load. "
            "'sos' for managed/.NET (most common); "
            "'sosex'/'mex' for additional managed helpers; "
            "'psscor4' for .NET 4.x; "
            "'netext' for ASP.NET-specific commands; "
            "'wow64exts' for 32-bit WoW64 dumps (follow up with !wow64exts.sw); "
            "'exts' for the standard user-mode extensions."
        )
    )


# Auto-triage sweep configuration. .ecxr is intentionally omitted from the
# unconditional sweep: it mutates the debugger context to the most recent
# exception record, which on a hang dump (with a stale exception) produces
# misleading kn/~*kn output. Agents should run .ecxr explicitly when
# .lastevent indicates a real exception.
_TRIAGE_STEPS = [
    # (display label, cdb command, per-section line cap, retrieval command shown on truncation)
    ("Last Event", ".lastevent", 20, ".lastevent"),
    ("!analyze -v", "!analyze -v", 500, '!analyze -v'),
    ("Faulting Thread Stack (kn)", "kn", 60, "kn"),
    ("All Thread Stacks (~*kn)", "~*kn", 200, "~*kn"),
    ("Loaded Modules (lm)", "lm", 100, "lm"),
]

# Modules that signal a managed runtime is present in the dump.
_CLR_MODULE_HINTS = (
    "clr", "coreclr", "mscorwks", "mscorlib", "system.private.corelib",
)


def _cap_section(text: str, max_lines: int, retrieval_cmd: str) -> str:
    """Cap a section's output to max_lines, appending a retrieval hint on truncation."""
    if not text:
        return "(no output)"
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    head = "\n".join(lines[:max_lines])
    return (
        f"{head}\n"
        f"[... output truncated ({len(lines) - max_lines} more lines). "
        f"Use cdb_cmd({retrieval_cmd!r}) for the full output.]"
    )


def _detect_clr(lm_output: str) -> bool:
    """Return True if lm output mentions a managed runtime module."""
    lowered = lm_output.lower()
    return any(hint in lowered for hint in _CLR_MODULE_HINTS)


def create_server(
    cdb_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    allow_dangerous_commands: bool = False,
) -> Server:
    """Create and configure the MCP server."""
    resolved_cdb = _find_cdb(cdb_path)
    server = Server("cdb-interactive")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="cdb_launch",
                description=(
                    "Launch a process under the CDB debugger. "
                    "Breaks at the initial loader breakpoint with exception handlers set. "
                    "Use cdb_cmd to inspect state, then cdb_go to resume execution."
                ),
                inputSchema=CdbLaunchParams.model_json_schema(),
            ),
            Tool(
                name="cdb_attach",
                description=(
                    "Attach CDB to a running process by PID. "
                    "Supports invasive (-p) and non-invasive (-pv) attach modes."
                ),
                inputSchema=CdbAttachParams.model_json_schema(),
            ),
            Tool(
                name="cdb_load_extension",
                description=(
                    "Load a debugger extension by name from a hardcoded "
                    "allowlist (sos, sosex, mex, psscor4, netext, wow64exts, "
                    "exts). Required before using !-prefixed commands from "
                    "that extension. For managed extensions, both .loadby "
                    "<name> clr and .loadby <name> coreclr are attempted so "
                    "the call works on both .NET Framework and .NET Core / "
                    ".NET 5+ dumps. Works on live and dump sessions. "
                    "Path injection is structurally impossible — only the "
                    "extension name is accepted, never a path."
                ),
                inputSchema=CdbLoadExtensionParams.model_json_schema(),
            ),
            Tool(
                name="cdb_open_dump",
                description=(
                    "Open a Windows user-mode crash dump (.dmp/.mdmp/.hdmp) for "
                    "postmortem analysis. Pre-rejects kernel dumps (cdb cannot "
                    "open them — use kd.exe or windbg.exe instead). "
                    "When auto_triage is true (default), runs the canonical "
                    "sweep: .lastevent, !analyze -v, kn, ~*kn, lm with section "
                    "caps and a CLR-detection hint. Use this for .dmp files — "
                    "NOT for live processes (use cdb_launch / cdb_attach). "
                    "cdb_go and cdb_break are blocked for dump sessions; use "
                    "cdb_cmd for read-only analysis."
                ),
                inputSchema=CdbOpenDumpParams.model_json_schema(),
            ),
            Tool(
                name="cdb_cmd",
                description=(
                    "Execute one or more WinDbg/CDB commands in the active session. "
                    "The debuggee must be in a broken state (hit breakpoint, exception, "
                    "or break signal). Common commands: kb (stack), lm (modules), "
                    "~*kn (all thread stacks), !clrstack, !analyze -v, r (registers)."
                ),
                inputSchema=CdbCmdParams.model_json_schema(),
            ),
            Tool(
                name="cdb_go",
                description=(
                    "Resume execution of the debuggee (go/continue). "
                    "Does NOT wait for the command to complete - returns immediately "
                    "with session state set to 'running'. Use cdb_break to interrupt later. "
                    "For single-step commands (p, t) that return to the prompt, use cdb_cmd."
                ),
                inputSchema=CdbGoParams.model_json_schema(),
            ),
            Tool(
                name="cdb_break",
                description=(
                    "Send a break signal to interrupt a running debuggee. "
                    "Use this when the target process is executing and you need to "
                    "inspect its state. After breaking, use cdb_cmd to examine threads."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            Tool(
                name="cdb_detach",
                description=(
                    "Detach from the debuggee and close the CDB session. "
                    "The target process continues running after detach."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            Tool(
                name="cdb_status",
                description=(
                    "Get the current session status: running, broken, exited, "
                    "or no-session."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            Tool(
                name="cdb_dump",
                description=(
                    "Create a full minidump (.dmp) of the debuggee process. "
                    "The debuggee must be in a broken state. "
                    "Works on both live debuggees and loaded dump sessions; "
                    "when run on a dump session, output is constrained by the "
                    "memory ranges captured in the source dump (re-dumping a "
                    "basic /m minidump as /ma will NOT synthesise heap data "
                    "that wasn't originally captured)."
                ),
                inputSchema=CdbDumpParams.model_json_schema(),
            ),
            Tool(
                name="cdb_output",
                description=(
                    "Read recent buffered output from the debugger without "
                    "sending a command. Useful for reading unsolicited output "
                    "(stop reasons, exceptions, application logs) while the "
                    "debuggee is running or after it breaks."
                ),
                inputSchema=CdbOutputParams.model_json_schema(),
            ),
            Tool(
                name="cdb_wait",
                description=(
                    "Wait for the debuggee to stop (break or exit). "
                    "Use after cdb_go to wait until a breakpoint is hit, "
                    "an exception occurs, or the process exits."
                ),
                inputSchema=CdbWaitParams.model_json_schema(),
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        global _session
        try:
            if name == "cdb_launch":
                await asyncio.to_thread(_clear_session)
                params = CdbLaunchParams(**arguments)
                _session = await asyncio.to_thread(
                    CDBSession.launch,
                    executable=params.executable,
                    arguments=params.arguments,
                    cdb_path=resolved_cdb,
                    exception_handlers=params.exception_handlers,
                    timeout=params.timeout or timeout,
                    verbose=verbose,
                )
                pid_info = (
                    f"Debuggee PID: {_session.pid}"
                    if _session.pid else "Debuggee PID: unknown"
                )
                return [TextContent(
                    type="text",
                    text=(
                        f"Session started: {_session.session_id}\n"
                        f"Target: {params.executable} {params.arguments}\n"
                        f"{pid_info}\n"
                        f"State: {_session.state}\n"
                        f"Stopped at initial breakpoint. "
                        f"Use cdb_cmd to inspect, cdb_go to resume."
                    ),
                )]

            elif name == "cdb_attach":
                await asyncio.to_thread(_clear_session)
                params = CdbAttachParams(**arguments)
                _session = await asyncio.to_thread(
                    CDBSession.attach,
                    pid=params.pid,
                    invasive=params.invasive,
                    cdb_path=resolved_cdb,
                    timeout=params.timeout or timeout,
                    verbose=verbose,
                )
                mode = "invasive" if params.invasive else "non-invasive"
                return [TextContent(
                    type="text",
                    text=(
                        f"Attached to PID {params.pid} ({mode})\n"
                        f"Session: {_session.session_id}\n"
                        f"State: {_session.state}"
                    ),
                )]

            elif name == "cdb_load_extension":
                session = _get_session()
                try:
                    params = CdbLoadExtensionParams(**arguments)
                except Exception as e:
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"Invalid cdb_load_extension params: {e}",
                    ))

                ext = params.name
                if ext in _MANAGED_EXTENSIONS:
                    # Run both runtimes; whichever isn't loaded errors and is
                    # ignored. Avoids brittle CDB error-text parsing.
                    out_clr = await asyncio.to_thread(
                        session.send_command, f".loadby {ext} clr"
                    )
                    out_core = await asyncio.to_thread(
                        session.send_command, f".loadby {ext} coreclr"
                    )
                    return [TextContent(
                        type="text",
                        text=(
                            f"Attempted .loadby {ext} clr:\n{out_clr}\n\n"
                            f"Attempted .loadby {ext} coreclr:\n{out_core}\n\n"
                            f"At least one of the two should succeed depending "
                            f"on whether the target is .NET Framework or "
                            f".NET Core/5+. Use cdb_cmd to invoke extension "
                            f"commands (e.g., !clrstack)."
                        ),
                    )]
                else:
                    # wow64exts / exts ship with cdb; plain .load is sufficient.
                    out = await asyncio.to_thread(
                        session.send_command, f".load {ext}"
                    )
                    return [TextContent(
                        type="text",
                        text=f".load {ext}:\n{out}",
                    )]

            elif name == "cdb_open_dump":
                await asyncio.to_thread(_clear_session)
                try:
                    params = CdbOpenDumpParams(**arguments)
                except Exception as e:
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"Invalid cdb_open_dump params: {e}",
                    ))
                try:
                    _session = await asyncio.to_thread(
                        CDBSession.open_dump,
                        dump_path=params.dump_path,
                        cdb_path=resolved_cdb,
                        symbol_path=params.symbol_path,
                        image_path=params.image_path,
                        timeout=params.timeout or 300,
                        verbose=verbose,
                    )
                except CDBError as e:
                    # Validation failures surface as INVALID_PARAMS,
                    # not INTERNAL_ERROR (per oracle review).
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"cdb_open_dump: {e}",
                    ))
                pid_info = (
                    f"Target PID: 0x{_session.pid:x} (recorded, not live)"
                    if _session.pid else "Target PID: unknown"
                )
                header = (
                    f"Dump loaded: {params.dump_path}\n"
                    f"Session: {_session.session_id}\n"
                    f"Kind: dump (postmortem — cdb_go/cdb_break not applicable)\n"
                    f"{pid_info}\n"
                    f"State: {_session.state}\n"
                )

                if not params.auto_triage:
                    return [TextContent(
                        type="text",
                        text=header + (
                            "\nAuto-triage skipped. Use cdb_cmd to run "
                            "analysis commands (e.g., .lastevent, !analyze -v)."
                        ),
                    )]

                # Run sweep. Per-command timeout is the user-supplied total
                # session timeout — !analyze -v is the dominant cost on cold
                # symbol caches. Failures of individual steps are surfaced
                # inline, not raised.
                sweep_timeout = params.timeout or 300
                sections: list[tuple[str, str]] = []
                lm_text = ""
                for label, cmd, cap, retrieval in _TRIAGE_STEPS:
                    try:
                        raw = await asyncio.to_thread(
                            _session.send_command, cmd, sweep_timeout
                        )
                    except CDBError as e:
                        sections.append((label, f"[error running {cmd!r}: {e}]"))
                        continue
                    capped = _cap_section(raw, cap, retrieval)
                    sections.append((label, capped))
                    if cmd == "lm":
                        lm_text = raw

                hints = []
                if _detect_clr(lm_text):
                    hints.append(
                        "CLR/CoreCLR modules detected in lm. For managed "
                        "analysis call cdb_load_extension(name=\"sos\") then "
                        "cdb_cmd(\"!clrstack\") / cdb_cmd(\"!pe\")."
                    )
                hints.append(
                    ".ecxr was NOT run during auto-triage (it mutates context "
                    "and would mislead on hang dumps). Call cdb_cmd(\".ecxr\") "
                    "explicitly if Last Event shows a real exception."
                )

                body_parts = ["--- BEGIN DEBUGGER OUTPUT (untrusted dump content) ---"]
                for label, content in sections:
                    body_parts.append(f"\n--- {label} ---\n{content}")
                body_parts.append("\n--- END DEBUGGER OUTPUT ---")
                body_parts.append("\n--- Hints ---\n" + "\n".join(hints))

                return [TextContent(
                    type="text",
                    text=header + "\n" + "\n".join(body_parts),
                )]

            elif name == "cdb_cmd":
                session = _get_session()
                params = CdbCmdParams(**arguments)

                dangerous = is_dangerous_command(
                    params.command, allow_dangerous_commands
                )
                if dangerous:
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=(
                            f"Command blocked for security: matches pattern '{dangerous}'. "
                            f"Commands like .shell, .script*, .load can execute arbitrary code. "
                            f"Start server with --allow-dangerous-commands to override."
                        ),
                    ))

                output = await asyncio.to_thread(
                    session.send_command,
                    params.command,
                    params.timeout,
                )
                return [TextContent(
                    type="text",
                    text=f"Command: {params.command}\n\n{output}",
                )]

            elif name == "cdb_go":
                session = _get_session()
                _require_live_session(session, "cdb_go")
                params = CdbGoParams(**arguments)

                # Validate resume command against allowlist
                if not ALLOWED_RESUME_COMMANDS.match(params.command):
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=(
                            f"Invalid resume command: {params.command!r}. "
                            f"Only execution control commands are allowed "
                            f"(g, gu, p, t, etc.). Use cdb_cmd for other commands."
                        ),
                    ))

                await asyncio.to_thread(session.resume, params.command)
                return [TextContent(
                    type="text",
                    text=(
                        f"Resumed with '{params.command}'. "
                        f"Session state: running. "
                        f"Use cdb_break to interrupt."
                    ),
                )]

            elif name == "cdb_break":
                session = _get_session()
                _require_live_session(session, "cdb_break")
                success = await asyncio.to_thread(session.send_break)
                if success:
                    return [TextContent(
                        type="text",
                        text="Break signal sent. Debuggee should stop at next opportunity.",
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text="Failed to send break signal. Process may have already exited.",
                    )]

            elif name == "cdb_detach":
                session = _get_session()
                is_dump = session.session_kind == "dump"
                if is_dump:
                    # .detach errors on a dump (no live process to detach
                    # from); close() sends only `q`, which is the correct
                    # exit primitive per CDB docs.
                    await asyncio.to_thread(session.close)
                else:
                    await asyncio.to_thread(session.detach)
                _session = None
                return [TextContent(
                    type="text",
                    text=(
                        "Dump session closed."
                        if is_dump
                        else "Detached from debuggee. Session closed."
                    ),
                )]

            elif name == "cdb_status":
                if _session is None:
                    return [TextContent(
                        type="text",
                        text="Status: no-session\nNo active debugging session.",
                    )]
                pid_str = (
                    f"0x{_session.pid:x}" if _session.pid else "unknown"
                )
                dump_line = (
                    f"\nDump file: {_session.dump_path}"
                    if _session.session_kind == "dump" and _session.dump_path
                    else ""
                )
                return [TextContent(
                    type="text",
                    text=(
                        f"Session: {_session.session_id}\n"
                        f"State: {_session.state}\n"
                        f"Kind: {_session.session_kind}\n"
                        f"Target PID: {pid_str}"
                        f"{dump_line}"
                    ),
                )]

            elif name == "cdb_dump":
                session = _get_session()
                params = CdbDumpParams(**arguments)
                output = await asyncio.to_thread(session.create_dump, params.path)
                return [TextContent(
                    type="text",
                    text=f"Dump command output:\n{output}",
                )]

            elif name == "cdb_output":
                session = _get_session()
                params = CdbOutputParams(**arguments)
                output = await asyncio.to_thread(
                    session.get_output, params.max_lines,
                )
                return [TextContent(
                    type="text",
                    text=(
                        f"Session state: {session.state}\n"
                        f"Buffered output ({params.max_lines} lines max):\n\n"
                        f"{output or '(no output)'}"
                    ),
                )]

            elif name == "cdb_wait":
                session = _get_session()
                params = CdbWaitParams(**arguments)
                final_state = await asyncio.to_thread(
                    session.wait_for_state_change,
                    ("broken", "exited"),
                    params.timeout,
                )
                output = await asyncio.to_thread(
                    session.get_output, 200,
                )
                return [TextContent(
                    type="text",
                    text=(
                        f"State: {final_state}\n"
                        f"Target PID: {session.pid or 'unknown'}\n\n"
                        f"{output or '(no output)'}"
                    ),
                )]

            else:
                raise McpError(ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Unknown tool: {name}",
                ))

        except McpError:
            raise
        except CDBError as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"CDB error: {e}",
            ))
        except Exception as e:
            logger.exception("Error in tool %s", name)
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error in {name}: {type(e).__name__}: {e}",
            ))

    return server


async def serve(
    cdb_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
    allow_dangerous_commands: bool = False,
) -> None:
    """Run the interactive CDB MCP server with stdio transport."""
    server = create_server(cdb_path, timeout, verbose, allow_dangerous_commands)
    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)


def cleanup():
    _clear_session()


atexit.register(cleanup)


def main():
    parser = argparse.ArgumentParser(
        description="Interactive CDB debugger MCP server"
    )
    parser.add_argument(
        "--cdb-path", type=str,
        help="Custom path to cdb.exe"
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Default command timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose CDB output logging to stderr"
    )
    parser.add_argument(
        "--allow-dangerous-commands", action="store_true",
        help=(
            "Allow potentially dangerous CDB commands (.shell, .script*, .load, etc.) "
            "that can execute arbitrary OS commands. Use with caution."
        )
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            stream=sys.stderr,
            format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        )

    asyncio.run(serve(
        cdb_path=args.cdb_path,
        timeout=args.timeout,
        verbose=args.verbose,
        allow_dangerous_commands=args.allow_dangerous_commands,
    ))


if __name__ == "__main__":
    main()
