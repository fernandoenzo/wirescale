# AGENTS.md — Wirescale

Guide for AI agents working on this codebase. Read this file completely before making any changes.

## What is Wirescale

Wirescale is a Linux CLI tool that upgrades Tailscale connections between two machines into pure, kernel-level WireGuard tunnels. It uses Tailscale's UDP hole-punching to discover endpoints, then establishes a fully customizable WireGuard P2P connection that runs at kernel-level performance instead of Tailscale's userspace `wireguard-go`.

Requires root. Runs as a systemd-managed daemon. Licensed AGPLv3+. Python 3.11+.

## Project structure

```
wirescale/                          # Root
├── setup.py                        # Packaging (entry point: wirescale.wirescale:main)
├── requirements.txt                # cryptography, parallel-utils, websockets
├── install.sh / uninstall.sh       # System-level install scripts
├── bundle/                         # PyInstaller bundle assets
└── wirescale/                      # Main Python package
    ├── __main__.py                 # Entry point, sys.path modification
    ├── wirescale.py                # main() — CLI dispatch
    ├── version.py                  # VERSION, DATE
    ├── communications/             # Networking layer (WebSocket, UNIX, TCP)
    │   ├── common.py               # Shared state: CONNECTION_PAIRS, file_locker, Semaphores, constants
    │   ├── connection_pair.py      # ConnectionPair — the core connection abstraction
    │   ├── messages.py             # ErrorPair, ErrorMessages, Messages, TCPMessages, UnixMessages, ActionCodes, ErrorCodes, MessageFields
    │   ├── operations.py           # VPNOperation base class, UpgradeOperation, RecoverOperation — unified upgrade/recover flow
    │   ├── checkers.py             # Validation functions (config, interface, handshake, NAT, pubkeys)
    │   ├── systemd.py              # Systemd wrapper (already wraps systemctl — do NOT add to commands.py)
    │   ├── tcp_client.py           # TCPClient — initiator side, run(operation) drives the message loop
    │   ├── tcp_server.py           # TCPServer — responder side of the TCP WebSocket flow
    │   ├── unix_client.py          # UnixClient — local CLI process connecting to the daemon
    │   ├── unix_server.py          # UnixServer — daemon-side UNIX socket handler, separate upgrade()/recover()
    │   └── udp_server.py           # UDPServer — occupies port 41641 to prevent Tailscale conflicts
    ├── parsers/                    # CLI argument parsing
    │   ├── args.py                 # ARGS class (mutable global state)
    │   ├── parsers.py              # argparse parser definitions
    │   ├── utils.py                # Parser utility functions
    │   └── validators.py           # Argument validation functions
    ├── vpn/                        # VPN / WireGuard / Tailscale logic
    │   ├── commands.py             # Subprocess wrappers for wg, wg-quick, iptables, ip, sysctl
    │   ├── vpn_config.py           # VPNConfig — abstract base class for WGConfig and RecoverConfig
    │   ├── wgconfig.py             # WGConfig — new WireGuard tunnel configuration
    │   ├── recover.py              # RecoverConfig — recover a broken existing tunnel
    │   ├── exit_node.py            # ExitNode — exit-node routing management
    │   ├── tsmanager.py            # TSManager — Tailscale CLI wrapper (already a wrapper — do NOT add to commands.py)
    │   ├── iptables.py             # IPTABLES — iptables rule template holder
    │   └── watch.py                # ActiveSockets / ACTIVE_SOCKETS — deadlock prevention
    ├── scripts/                    # Shell helper scripts
    │   ├── wirescale-autoremove    # Autoremove script run by systemd-run
    │   └── wirescale-completion    # Bash completion script
    └── systemd/                    # systemd unit files
        ├── wirescaled.service
        └── wirescaled.socket
```

## Build and run

```bash
# Install dependencies
pip install -r requirements.txt

# Install system-wide (requires root)
sudo ./install.sh

# Run directly
sudo python3 -m wirescale daemon --start
sudo wirescale upgrade <peer_name>

# Compile-check a file (no tests exist)
python3 -m py_compile wirescale/path/to/file.py
```

There is no test suite. Verification is done by compile-checking (`python3 -m py_compile`) all modified files. Always use `python3`, never `python`.

## Important constants and helpers (common.py)

```python
CONFIG_DIR = Path('/etc/wirescale/')       # User config files
RUN_DIR = Path('/run/wirescale/')           # Runtime state, .conf files, control sockets
SOCKET_PATH = RUN_DIR / 'wirescaled.sock'   # UNIX socket path
TCP_PORT = 41642                            # TCP WebSocket server port
WIRESCALE_TABLE = 0xA08D037A                # Custom routing table ID for exit-node
EXIT_NODE_MARK = WIRESCALE_TABLE + 1        # fwmark for exit-node interface
GLOB_MARK = EXIT_NODE_MARK + 1              # fwmark for non-exit-node peers
SHUTDOWN = Event()                          # Signals daemon shutdown across threads
CONNECTION_PAIRS: Dict[int, ConnectionPair] # Thread ID → ConnectionPair mapping
```

Other helpers in `common.py`:
- **`first_not_none(*values, default=None)`** — Returns the first non-`None` value, or `default`. Used extensively in `UnixServer` and `TCPServer` to merge CLI args with config-file values.
- **`check_with_timeout(func, timeout, sleep_time=0.5)`** — Polls `func()` until truthy or timeout. Returns `bool`.
- **`subprocess_run_tmpfile()`** — A replacement for `subprocess.run(capture_output=True)` that uses temporary files instead of pipes to avoid pipe-buffer deadlocks with large outputs. Used by `wg_quick_up()` in `commands.py`.
- **`BytesStrConverter`** — Utility class for base64/UTF-8 byte conversions, used in the recover flow's crypto operations.

## Architecture

### Daemon startup

When `wirescale daemon --start` runs inside systemd (`SYSTEMD_EXEC_PID` is set):
1. Copies the `wirescale-autoremove` script to `/run/wirescale/`.
2. `UDPServer.occupy_port_41641()` — Binds a dummy UDP socket to port 41641 to prevent Tailscale from using it (Wirescale manages port allocation itself).
3. Spawns three daemon threads:
   - `TCPServer.run_server()` — Listens on Tailscale IP, port 41642.
   - `UnixServer.run_server()` — Listens on the systemd-provided UNIX socket.
   - `ACTIVE_SOCKETS.watch()` — Deadlock monitor, polls every 15 seconds.
4. Blocks on all three `.result()` calls.

### Communication flow

There are four process roles and three socket types:

```
CLI process                Daemon (same machine)              Daemon (remote machine)
───────────                ─────────────────────              ──────────────────────
UnixClient ──UNIX socket──▶ UnixServer ──TCP WebSocket──▶ TCPServer
                              │                                    │
                              └─ creates VPNOperation              │
                              │  and calls TCPClient.run()         │
                              │         │                           │
                              │         └────TCP WebSocket─────────┘
```

1. **UnixClient** (CLI process): Connects to the local daemon via UNIX socket. Sends the user's command (upgrade/recover/stop). Receives status messages until success or error.
2. **UnixServer** (daemon): Receives the UNIX message, queues it through semaphores, creates a `VPNOperation` (`UpgradeOperation` or `RecoverOperation`), and calls `TCPClient.run(operation)`.
3. **TCPClient** (daemon, initiator side): Opens a TCP WebSocket to the remote peer's daemon. The unified `run(operation)` method drives the message loop: TOKEN → HELLO → ACK → operation-specific request/response → GO → execute. The `VPNOperation` strategy object (`UpgradeOperation` or `RecoverOperation`) encapsulates the differences between upgrade and recover flows.
4. **TCPServer** (daemon, responder side): Receives the TCP WebSocket connection. Processes the upgrade/recover request. Sends back the response. Waits for GO, then executes its side.

### Threading model

Each connection runs in its own thread. Thread identity (`threading.get_ident()`) is the key used to look up the `ConnectionPair` for the current connection in the global `CONNECTION_PAIRS` dict.

**Semaphores** (from `parallel_utils.thread.StaticMonitor`):
- `CLIENT`: Serializes outgoing client requests.
- `SERVER`: Serializes incoming server requests.
- `EXCLUSIVE`: Only one connection (client or server) can hold this at a time.
- `WAIT_IF_SWITCHED`: Used during deadlock resolution.

The `ACTIVE_SOCKETS` singleton (`watch.py`) monitors for deadlocks every 15 seconds. When both a client and server connection are stalled (both waiting for the exclusive semaphore), it performs a deterministic switch to break the deadlock.

### Error handling flow

`ErrorMessages.send_error_message()` is the central error dispatch. It:
1. Prints the local error message to stderr.
2. Sends the error to the local UNIX socket (for the CLI process to display).
3. Sends the remote error to the TCP WebSocket (for the remote peer to display).
4. Closes all sockets.
5. Calls `sys.exit(exit_code)` — which in a thread raises `SystemExit`, terminating only that thread.

`ErrorMessages.send_paired_error()` is a convenience wrapper for errors that have both a local and remote variant (stored as `ErrorPair`). It auto-injects `my_name`, `my_ip`, `peer_name`, `peer_ip` from the current `ConnectionPair`.

### Subprocess wrapper layers

There are three wrapper layers, each wrapping a specific set of tools. Do NOT merge them:

| Layer | File | Wraps | Notes |
|-------|------|-------|-------|
| `commands.py` | `vpn/commands.py` | `wg`, `wg-quick`, `iptables`, `ip`, `sysctl` | New centralized wrappers |
| `systemd.py` | `communications/systemd.py` | `systemctl`, `systemd-run` | Already existed as a wrapper — do NOT move to commands.py |
| `tsmanager.py` | `vpn/tsmanager.py` | `tailscale`, `ss`, `ping` | Already existed as a wrapper — do NOT move to commands.py |

## Conventions and rules

### Things you must NEVER change

1. **Bare `except:` clauses** — They are intentional throughout the codebase. Every single one serves a purpose (catching unpredictable failures from external tools, crypto operations, etc.). Do not narrow them, do not add exception types, do not touch them.

2. **`collections.deque(..., maxlen=0)` pattern** — This is a documented Python idiom for consuming a generator for its side effects without allocating a list. It appears in `common.py`, `wgconfig.py`, and `exit_node.py`. Do not replace it with `for` loops or list comprehensions.

3. **`sys.exit()` as control flow** — Used extensively, especially in threaded contexts where `sys.exit()` raises `SystemExit` to terminate only the calling thread. This is deliberate. Do not refactor it out; the scope is too massive and the pattern is intentional.

4. **`sys.path` modification in `__main__.py`** — `sys.path.insert(0, str(GLOBAL_PARENT))` exists for PyInstaller compatibility and specific import contexts. Do not remove or modify it.

5. **`ExitNode.RULES` dict mutation** — The `RULES` class attribute is deliberately mutated in-place in `add_ip_rules()` (setting index 8 of the EXIT_NODE rule to the fwmark value). Each CLI invocation runs in a separate process, so there is no state leakage. Do not "fix" this by making copies.

6. **The ARGS class pattern** — `ARGS` is a mutable class (never instantiated) used as global state for parsed arguments. All attributes are class-level, set directly on the class. Do not convert it to a dataclass, NamedTuple, or instance-based pattern.

### Code style

- **No logging framework** — The project uses `print()` for all output (stdout for info, stderr for errors). Do not introduce `logging`.
- **No tests** — There is no test suite. Verify changes with `python3 -m py_compile`.
- **No emojis in code** unless the user explicitly requests them.
- **Do not rename variables** without explicit approval from the user.
- **Import ordering** — Imports follow PyCharm's default sorting, organized in three groups separated by a single blank line (no blank lines within a group):
  1. **Standard library** — bare `import xxx` first (alphabetically), then `from xxx import yyy` (alphabetically by module path)
  2. **Third-party packages** — alphabetically by package name
  3. **Local project imports** — `from wirescale...` alphabetically by module path; `if TYPE_CHECKING:` blocks at the end

  Within each `from xxx import a, b, c` line, names are sorted alphabetically (case-insensitive).
- **Commit messages** — Brief, imperative mood, one line. Commits must always be signed: `git commit -S`.
- **Respond in Spanish** when the user writes in Spanish.

### Error message constants

Error messages in `ErrorMessages` follow two patterns:

1. **`ErrorPair` (NamedTuple)** — For errors that have both a local and remote variant. Used with `send_paired_error()`, which auto-injects `my_name`, `my_ip`, `peer_name`, `peer_ip` from the connection pair. Example:
   ```python
   INTERFACE_EXISTS = ErrorPair(
       local="Error: A network interface '{interface}' already exists",
       remote="Error: A network interface '{interface}' already exists in remote peer '{my_name}' ({my_ip})")
   ```

2. **Plain strings** — For errors that are only shown locally, or that have anomalous usage patterns. Three standalone remote constants remain: `REMOTE_CONFIG_ERROR` (used with raw exception strings), `REMOTE_MISSING_WIRESCALE` (anomalous usage as local message), `REMOTE_CLOSED` (used in separate contexts).

When adding a new error that has both local and remote variants, always use `ErrorPair` and `send_paired_error()`. The remote template uses `my_name`/`my_ip` (the sender's identity from the remote peer's perspective).

### LSP errors

All LSP errors shown during editing are **pre-existing** in the project. They stem from type annotation mismatches (e.g., `None` assigned to typed fields, `parallel_utils` not resolvable). They are not caused by refactoring changes. Do not try to fix them unless the user explicitly asks.

### Key patterns to understand

**`ConnectionPair` as iterator**: Iterating over a `ConnectionPair` yields WebSocket messages from `remote_socket` with a 15-second timeout. On timeout, it spawns a background thread to ping-check the peer via Tailscale. On `ConnectionClosedError`, it reports the error and exits. On `ConnectionClosedOK`, it cleanly stops.

**`file_locker()` context manager**: A file-based exclusive lock (`fcntl.flock`) on `/run/wirescale/control/locker`. Used to serialize operations that touch Tailscale state or perform name resolution.

**`subprocess_run_tmpfile()`**: A replacement for `subprocess.run(capture_output=True)` that uses temporary files instead of pipes to avoid pipe-buffer deadlocks with large outputs. Located in `common.py`, used by `wg_quick_up()` in `commands.py`.

**Perspective swap in remote error messages**: In remote error templates, `{my_name}`/`{my_ip}` refers to the machine that detected the error (the sender), because from the remote peer's perspective, that machine is "the remote peer". The `send_paired_error()` method handles this transparently by injecting the current pair's identity fields.

## Branching and integration workflow

New features and refactors go in dedicated branches. Always ask the user before creating a branch or making changes.

Branch naming conventions:
- `feature/<name>` for new functionality
- `refactor/<name>` for structural changes

Integration into `master` follows this sequence:

1. **Cherry-pick** the code commit(s) onto `master`.
2. **Compile-check** all modified files (`python3 -m py_compile`).
3. **Update documentation** (`AGENTS.md`, `README`, etc.) if the change affects architecture, conventions, or project structure. Commit separately.
4. **Push** to remote.
5. **Delete** the feature branch (local and remote).

Safety checkpoints: stop and ask the user before continuing if any git operation fails (cherry-pick conflict, push rejection, etc.).
