"""MCP server for interactive CDB debugging sessions.

Provides tools to launch processes under CDB, attach to running processes,
send debugger commands, break into execution, create dumps, and detach.
"""

import argparse
import asyncio
import atexit
import logging
import re
import sys
from typing import Optional

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

from cdb_session import CDBSession, CDBError, _find_cdb, ALLOWED_RESUME_COMMANDS

logger = logging.getLogger(__name__)

# Dangerous CDB commands that can execute arbitrary OS commands or load code
# These are blocked by default to prevent prompt injection attacks
DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"^\s*\.shell\b", re.IGNORECASE),      # OS command execution
    re.compile(r"^\s*\.script\w*\b", re.IGNORECASE),  # Script loading/execution
    re.compile(r"^\s*\.load\b", re.IGNORECASE),       # Extension DLL loading
    re.compile(r"^\s*\.loadby\b", re.IGNORECASE),     # Extension DLL loading
    re.compile(r"^\s*!for_each_\w+", re.IGNORECASE),  # Iteration with command execution
    re.compile(r"^\s*!shell\b", re.IGNORECASE),       # Shell extension alias
    re.compile(r"^\s*\.writemem\b", re.IGNORECASE),   # Write to memory file
    re.compile(r"^\s*\.create\b", re.IGNORECASE),     # Create process
]

# Split commands on semicolons and newlines (prevents newline-based bypass)
_CMD_SEPARATOR_RE = re.compile(r"[;\r\n]+")


def _is_dangerous_command(command: str, allow_dangerous: bool = False) -> Optional[str]:
    """Check if a command matches dangerous patterns.

    Returns the matched pattern description if dangerous, None if safe.
    """
    if allow_dangerous:
        return None

    # Split by semicolons AND newlines to prevent bypass
    for subcmd in _CMD_SEPARATOR_RE.split(command):
        subcmd = subcmd.strip()
        if not subcmd:
            continue
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if pattern.match(subcmd):
                return pattern.pattern
    return None

# Single active session (one debugger at a time)
_session: Optional[CDBSession] = None


def _get_session() -> CDBSession:
    if _session is None:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="No active debugging session. Use cdb_launch or cdb_attach first."
        ))
    return _session


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
                    "The debuggee must be in a broken state."
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

            elif name == "cdb_cmd":
                session = _get_session()
                params = CdbCmdParams(**arguments)

                dangerous = _is_dangerous_command(
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
                await asyncio.to_thread(session.detach)
                _session = None
                return [TextContent(
                    type="text",
                    text="Detached from debuggee. Session closed.",
                )]

            elif name == "cdb_status":
                if _session is None:
                    return [TextContent(
                        type="text",
                        text="Status: no-session\nNo active debugging session.",
                    )]
                return [TextContent(
                    type="text",
                    text=(
                        f"Session: {_session.session_id}\n"
                        f"State: {_session.state}\n"
                        f"Target PID: {_session.pid or 'unknown'}"
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
