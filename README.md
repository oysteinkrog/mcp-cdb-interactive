# mcp-cdb-interactive

Interactive CDB debugger MCP server for Claude Code. Launch processes under CDB, attach to running processes, send debugger commands, break into execution, create dumps, and detach.

## Setup

```bash
pip install -r requirements.txt
```

## Claude Code configuration

Add to `~/.claude.json` under `mcpServers`:

```json
{
  "cdb-interactive": {
    "type": "stdio",
    "command": "cmd.exe",
    "args": [
      "/c", "python",
      "<PATH_TO_REPO>/Tools/mcp-cdb-interactive/server.py",
      "--timeout", "120",
      "--verbose"
    ],
    "env": {
      "_NT_SYMBOL_PATH": "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols"
    }
  }
}
```

Replace `<PATH_TO_REPO>` with the actual path to your repository. The server will auto-detect `cdb.exe` from standard Windows SDK locations, or you can specify `--cdb-path` explicitly.

### Security Note

By default, dangerous CDB commands (`.shell`, `.script*`, `.load`, etc.) that can execute arbitrary OS commands are blocked. To enable them (use with caution):

```json
"args": ["...", "--allow-dangerous-commands"]
```

## Tools

| Tool | Description |
|------|-------------|
| `cdb_launch` | Launch a process under CDB with automatic exception handlers |
| `cdb_attach` | Attach to a running process by PID (invasive or non-invasive) |
| `cdb_cmd` | Execute WinDbg/CDB commands in the active session |
| `cdb_go` | Resume execution (go/continue) without waiting for completion |
| `cdb_break` | Send break signal to interrupt a running debuggee |
| `cdb_detach` | Detach from process and close session |
| `cdb_status` | Get current session state |
| `cdb_dump` | Create a minidump of the debuggee |
| `cdb_output` | Read buffered output without sending a command (tail while running) |
| `cdb_wait` | Wait for debuggee to stop (breakpoint, exception, or exit) |

## Usage examples

### Launch tests under debugger

```
cdb_launch(executable="dotnet.exe", arguments="test MyProject.csproj --configuration Debug --no-build")
```

### Attach to hung process

```
cdb_attach(pid=12345, invasive=false)
cdb_cmd(command="~*kn")
cdb_dump(path="C:\\temp\\hang.dmp")
cdb_detach()
```

### Catch crash

```
cdb_launch(executable="MyApp.exe")
# ... app crashes, CDB breaks in ...
cdb_cmd(command="!analyze -v")
cdb_cmd(command="!clrstack")
cdb_dump(path="C:\\temp\\crash.dmp")
```
