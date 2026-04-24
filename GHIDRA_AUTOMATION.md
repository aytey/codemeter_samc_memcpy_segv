# Ghidra GUI Automation

This note documents the "open GUI headless" workflow for this workspace: run a
real Ghidra GUI on an existing virtual display, but remove the Andrew click
path entirely.

The goal is:

- no manual FrontEnd project selection
- no manual CodeBrowser launch
- no manual "open the expected binary"
- a live GUI-backed GhidraMCP session that Codex can use immediately

## Current Entry Point

Use:

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py
```

The launcher is in
[ghidra_scripts/start_codex_ghidra_gui.py](/home/avj/clones/codemeter_samc_memcpy_segv/ghidra_scripts/start_codex_ghidra_gui.py:1).

By default it launches Ghidra on `DISPLAY=:100` and validates that
`/tmp/.X11-unix/X100` exists first. You can override that with `--display`.

It assumes:

- Ghidra is installed at `/home/avj/ghidra/ghidra_12.0.4_PUBLIC`
- the target project is
  `/home/avj/ghidra_projects/codemeter_samc_memcpy_segv/CodeMeterLin_import_only.gpr`
- the target program path inside the project is `/CodeMeterLin`

## What The Launcher Does

The launcher removes the human steps in this order:

1. Patches Ghidra FrontEnd config so `com.xebyte.GhidraMCPPlugin` loads in the
   FrontEnd before any CodeBrowser is open.
2. Updates Ghidra startup preferences so the expected project is the startup
   project.
3. Optionally restarts Ghidra if requested.
4. Launches `ghidraRun` on the selected display unless Ghidra is already
   running.
5. Waits for the FrontEnd GhidraMCP UDS socket for the target project.
6. Calls `/open_program?path=/CodeMeterLin` over that socket.
7. Lets Ghidra create or reuse CodeBrowser internally.

This means Andrew does not need to:

- click the project in FrontEnd
- open CodeBrowser
- open the binary
- click "Start Server"

## Why This Works

The GhidraMCP plugin already supports the last mile:

- `open_program` is GUI-only and requires a project to already be open
- if no CodeBrowser exists, it launches one internally

Relevant implementation:

- [ProgramScriptService.java](/home/avj/clones/ghidra-mcp/src/main/java/com/xebyte/core/ProgramScriptService.java:428)
- [ProgramScriptService.java](/home/avj/clones/ghidra-mcp/src/main/java/com/xebyte/core/ProgramScriptService.java:708)

The plugin also auto-starts UDS in the constructor on Linux when loaded in the
FrontEnd:

- [GhidraMCPPlugin.java](/home/avj/clones/ghidra-mcp/src/main/java/com/xebyte/GhidraMCPPlugin.java:257)

So the real automation problem was not "how do we open the program", but
"how do we guarantee the FrontEnd loads the plugin and starts on the right
project without Andrew touching the GUI."

## FrontEnd Autoload

The launcher patches:

- `/home/avj/.config/ghidra/ghidra_12.0.4_PUBLIC/FrontEndTool.xml`

It ensures the `Utility` package contains:

```xml
<INCLUDE CLASS="com.xebyte.GhidraMCPPlugin" />
```

That is the Linux equivalent of the existing PowerShell deployment logic in:

- [ghidra-mcp-setup.ps1](/home/avj/clones/ghidra-mcp/ghidra-mcp-setup.ps1:1004)

## Startup Project Selection

The launcher updates these keys in:

- `/home/avj/.config/ghidra/ghidra_12.0.4_PUBLIC/preferences`

Keys:

- `LastOpenedProject`
- `LastSelectedProjectDirectory`
- `ProjectDirectory`
- `RECENT_0`
- `RecentProjects`

The target project root is:

```text
/home/avj/ghidra_projects/codemeter_samc_memcpy_segv/CodeMeterLin_import_only
```

This is enough for Ghidra to reopen the expected project on startup.

## UDS Discovery And Bridge Compatibility

There are two related pieces here.

### 1. FrontEnd MCP Socket

The launcher waits for `/mcp/instance_info` on a Ghidra UDS socket whose
reported project is `CodeMeterLin_import_only`.

This gives a deterministic "FrontEnd is ready" signal without using GUI
introspection or sleeps alone.

### 2. Codex-Side Bridge Discovery

The Codex-side bridge had a discovery gap when its environment lacked
`XDG_RUNTIME_DIR`. In that case it could miss the real socket under
`/run/user/$UID/ghidra-mcp`.

That was patched in:

- [bridge_mcp_ghidra.py](/home/avj/clones/ghidra-mcp/bridge_mcp_ghidra.py:117)
- [bridge_mcp_ghidra.py](/home/avj/clones/ghidra-mcp/bridge_mcp_ghidra.py:318)

The launcher also creates compatibility symlinks in the old TMPDIR-style
locations so older bridge processes still see the same socket.

## Usage Patterns

### Normal Use

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py
```

Use this when:

- the display is already set
- you want the target project and binary opened automatically
- you do not want to restart a healthy running Ghidra unless needed

### Force A Fresh GUI Session

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py --restart-if-running
```

Use this when:

- Ghidra is already running on the wrong project
- you want a clean known-good startup state

### Reuse Live Ghidra Without Launching

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py --no-launch
```

Use this when:

- Ghidra is already open
- you only want to patch config, wait for FrontEnd MCP, and open the expected
  program

### Start And Auto-Analyze

```bash
python3 ghidra_scripts/start_codex_ghidra_gui.py --auto-analyze
```

Use this only when you want Ghidra auto-analysis kicked off immediately after
the program is opened.

## Expected Output

A successful run prints something like:

```text
Ghidra user dir: /home/avj/.config/ghidra/ghidra_12.0.4_PUBLIC
FrontEnd config updated: False
Preferences updated: False
Target project: /home/avj/ghidra_projects/codemeter_samc_memcpy_segv/CodeMeterLin_import_only
Socket: /run/user/1000/ghidra-mcp/ghidra-3044599.sock
open_program response: {"success":true,"message":"Program already open, switched to it","name":"CodeMeterLin","path":"/CodeMeterLin"}
```

Important interpretation:

- `FrontEnd config updated: False` means the config was already patched
- `Preferences updated: False` means the startup project was already pinned
- `Program already open, switched to it` is still success

## Failure Modes

### `DISPLAY is not set`

The launcher does not create a display. It expects one to already exist.

### Timed out waiting for FrontEnd MCP socket

This means one of:

- Ghidra did not start successfully
- the FrontEnd did not load `GhidraMCPPlugin`
- Ghidra opened a different project than expected

### `/open_program` returns an error

Typical causes:

- the project did not open
- `/CodeMeterLin` does not exist in the selected project
- Ghidra is still busy starting up

## Scope

This automation is workspace-specific, not generic. The defaults are pinned to
the CodeMeter crash project because that is the only target that matters here.

If another workspace needs the same pattern, duplicate the launcher and change:

- `DEFAULT_GHIDRA_PATH`
- `DEFAULT_PROJECT`
- `DEFAULT_PROGRAM`

## Verification Status

This path was verified against a live Ghidra session in this environment.

Observed success:

- FrontEnd MCP socket discovered for `CodeMeterLin_import_only`
- `/open_program` succeeded for `/CodeMeterLin`
- no manual GUI action was required
