# mshbox

Run **one command** on Windows inside a per-run [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
with restricted filesystem and network access. No admin rights, no UAC prompt, no driver, no service,
no firewall rule, no compiled helper, **standard-library Python only** (ctypes + Win32).

> **Status: alpha and unaudited.** The built-in `selftest` passes 7/7 on one real machine (Windows 11,
> Python 3.14, standard non-admin user). It has **not** been tried on other Windows versions, so run
> `mshbox selftest` on yours before you rely on it, and read [SECURITY.md](SECURITY.md). Items still
> unconfirmed are listed under [Verification status](#verification-status).

mshbox was written as an optional wrapper for a terminal AI agent (`mshlite`) that runs shell commands
written by an LLM **on the user's own machine**. The goal is **damage control**: stop a mistaken or
prompt-injected command from writing outside the project, reading your secrets, or using the network.
It is **not** a boundary against deliberate malware.

## Quick start

```bat
py mshbox.py selftest

:: batch file: relative name + call, with --cwd set to the folder that holds it
py mshbox.py run --rw C:\work\proj --cwd C:\work\proj -- cmd.exe /d /c call build.bat

:: Python: use a copy of the interpreter in a folder you own (see "Install location matters")
py mshbox.py run --rw C:\work\proj --ro C:\work\py --net --timeout 60 -- C:\work\py\python.exe tool.py

py mshbox.py cleanup
```

Requires Windows 8+ (AppContainer) and Python 3.8+. The program is a single file, `mshbox.py`; copy it anywhere.
No administrator rights are needed for any command.

## What it protects

| Goal | How |
|---|---|
| No writes outside the paths you name | AppContainer can access **nothing** by default. Only `--rw` paths are writable. |
| Secrets stay unreadable | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.mshlite`, browser profiles, etc. are **never granted**, and mshbox *refuses* any grant that equals, contains or sits inside them (see `SECRET_REL`). |
| No network by default | The container has no capabilities. `--net` adds only `internetClient` (outbound internet). |
| No runaway trees | A Job Object with kill-on-close, optional `--mem` / `--procs`; the whole tree is killed on timeout, Ctrl+C, or when the root process exits. |
| No secrets in the environment | The child gets a small allow-list of variables (`PATH`, `SystemRoot`, ...). `OPENAI_API_KEY` and friends are **dropped**; pass what you need with `--env KEY=VAL`. |
| Fail closed | If *any* step fails (profile, SID, ACL grant, job, spawn) mshbox prints the error, rolls back, and exits **125 without running the command**. There is no unsandboxed fallback. |
| No lasting changes | ACEs and the profile are removed in a `finally`; a journal written *before* any change lets `mshbox cleanup` (and every `run`) repair a crashed run. |

## What it does NOT protect

* **Anything you grant is fully exposed.** `--rw X` means the command can read, change and delete everything in X. `--ro X` means it can read everything in X.
* **It is not a security boundary against malware or a determined attacker.** No claim is made against kernel exploits, administrator-level attackers, or bugs in Windows itself.
* **Surrogate-process escapes are not claimed to be covered** (asking an unsandboxed service, COM/RPC server, scheduler, or the host agent itself to act on the sandbox's behalf).
* **Install location matters.** The program (and the interpreter it needs) must be readable by the container. System folders such as `C:\Windows` already are. A per-user install in a folder you own works, because the grant is inherited. An **all-users install elsewhere** (for example `D:\Python314`, whose files are owned by Administrators with inheritance blocked) cannot be shared with an AppContainer without admin rights: the program dies at startup with `0xC0000022`. Run a **copy** of the program from a folder you own and pass that folder with `--ro`.
* **A Python copy helper exists.** `mshbox.copy_runtime(dst)` copies a minimal CPython runtime (about 600 files, 10-15 s) into a folder you own and returns the new `python.exe`. `selftest` uses it, and `run` prints a hint when a program dies with `0xC0000022`.
* **`cmd.exe` quirks.** An AppContainer cannot read the drive root or the parent folders of your workspace. `cmd.exe` touches them for `dir` and when asked to run a batch file by absolute path, and then prints "Access is denied." Run batch files with a relative name and `call` (`cmd /d /c call build.bat` with `--cwd` set to the folder holding it) and prefer other tools for listings.
* **Localhost is blocked, even with `--net`.** Loopback exemptions need administrator rights, so mshbox does not attempt them. Local dev servers, `localhost` databases and anything that talks to `127.0.0.1` will not work.
* **Reads of world-readable system locations** (for example `C:\Windows`, `C:\Program Files`, which carry a read ACE for *ALL APPLICATION PACKAGES*) are possible and are intentionally not granted or blocked by mshbox. Whether *other* world-readable folders (for example under `C:\ProgramData` or a folder you created at a drive root) are readable depends on their ACLs and is **unverified**.
* `--net` is all-or-nothing: no per-host or per-port filtering, no proxy.
* **It does not hide the process from you** and does not sandbox the *host* (mshbox itself, or the agent calling it).

AppContainer ignores DENY ACEs, so mshbox cannot "deny" a secret inside a granted folder. The only protection
is **not granting** it: keep secrets outside any `--rw` / `--ro` path (mshbox also refuses the well-known ones).

## Threat model

**In scope (what mshbox tries to stop):**
an LLM-written or prompt-injected command that, through error or manipulation, tries to (1) write or delete files outside the project, (2) read credentials in your profile, (3) phone home or download things, (4) fork-bomb or leak memory, (5) leave background processes behind.

**Assumed:** you are an ordinary (non-admin) user on your own machine; the command is *not* purpose-built to defeat AppContainer; you choose the `--rw` / `--ro` paths and they contain nothing secret.

**Out of scope:** hostile native code that exploits Windows; other local users; attackers with admin/SYSTEM; data leaving through paths you granted; side channels; anything reachable through a surrogate process.

## How it works

1. **Profile & SID.** A per-run name `mshbox.<random>` → `CreateAppContainerProfile`; the SID is first derived with `DeriveAppContainerSidFromAppContainerName` and compared afterwards.
2. **Journal first.** A JSON record (run id, SID, owner PID + start time, planned grants) is written atomically to `%LOCALAPPDATA%\mshbox\journal` **before** any ACL or profile change. That folder is never granted to the container.
3. **Grants.** For each path, an additive, inheriting ACE for the container SID (`SetEntriesInAclW` + `SetNamedSecurityInfoW`): `--rw` → modify (read/write/execute/delete, **no** `WRITE_DAC`, `WRITE_OWNER` or `FILE_DELETE_CHILD`), `--ro` and the executable's folder → read+execute. Existing DACLs are never replaced: the new ACE is merged in and, later, only that SID's ACEs are removed. System folders that already carry an ALL APPLICATION PACKAGES read ACE are skipped.
4. **Job Object.** `KILL_ON_JOB_CLOSE`, optional job memory limit and active-process limit.
5. **Launch.** `CreateProcessW` + `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (and an explicit handle list), created **suspended**, assigned to the job, then resumed - so no code runs outside the job.
6. **Teardown (always).** Terminate the job, remove exactly the ACEs added, delete the profile, delete the journal. If anything fails the journal is kept and a warning tells you to run `mshbox cleanup`.

**Why AppContainer** (and not restricted tokens, integrity levels, a separate user, or a VM): it is the only built-in Windows mechanism that gives deny-by-default filesystem access *and* kernel-enforced network blocking without administrator rights. The price is compatibility - see [Known pitfalls](#known-pitfalls) and [Comparison](#comparison-with-other-tools).

## CLI

```
mshbox run [--rw PATH]... [--ro PATH]... [--net] [--timeout SEC] [--mem MB] [--procs N]
           [--cwd DIR] [--env KEY=VAL]... -- COMMAND [ARGS...]
mshbox selftest
mshbox cleanup
mshbox --version
```

* `--cwd` must be inside a granted path (or a system folder); default is the current directory.
* `--procs N` counts `cmd.exe` itself, so `cmd /c x.bat` needs at least 2.
* stdout / stderr are passed through unbuffered; stdin is `NUL`.
* A `.bat` / `.cmd` as COMMAND is run explicitly through `cmd.exe /c`.

| Exit code | Meaning |
|---|---|
| *n* | the command's own exit code |
| **124** | timeout - process tree killed |
| **125** | sandbox setup failed (or bad usage) - **command was not run** |
| 130 | interrupted with Ctrl+C - process tree killed |

## Python API

```python
import mshbox

p = mshbox.run(["cmd.exe", "/d", "/c", "call", "build.bat"], r"C:\work\proj",
               rw=[r"C:\work\proj"], net=False, timeout=120)
for line in p.stdout:          # binary pipe (stderr merged unless merge_stderr=False)
    ...
code = p.wait()                # 124 on timeout; p.kill(), p.poll(), p.returncode, p.timed_out
```

`mshbox.run` raises `mshbox.SandboxError` if setup fails; in that case **nothing was started and nothing is left behind**.
Extra keyword arguments: `mem_mb`, `procs`, `env`, `merge_stderr`, `cmdline` (a RAW command line used verbatim instead of C-runtime quoting of `argv`; needed for `cmd.exe /d /s /c <text>`, where cmd parses the text itself and `\"` is not an escape; `argv[0]` is still the executable that gets resolved and granted).

## Self-test

Run it on your own Windows machine **before trusting anything else**:

```bat
py mshbox.py selftest
py -m unittest tests.test_windows_integration -v
py -m unittest discover -s tests -v
```

`selftest` builds a temp workspace under `%TEMP%\mshbox_selftest_*` (it never touches real user files), copies a private Python runtime into it (first run only, 10-15 s) and prints PASS / FAIL / SKIP for:

1. write inside `--rw` succeeds
2. write outside `--rw` fails (your profile folder, a drive-root file, and a sibling temp folder)
3. a decoy "`.ssh`-like" secret in a temp folder is unreadable
4. network to `1.1.1.1:443` is blocked by default and works with `--net` (SKIP if the machine is offline)
5. a grandchild process is killed on timeout
6. ACEs, profile folder and journal are gone afterwards
7. a deliberately broken setup exits **125** and does not run the command

Notes on reading the results: check 2's drive-root target is weak on its own (ordinary users usually cannot create files in `C:\` anyway); the profile-folder and sibling-folder targets are the meaningful ones. A FAIL on 4 can mean "Python could not start inside the container" rather than "network leaked" - the detail text says which.

## Known pitfalls

* **Tools installed in your user profile** (Python, Node, git, Rust toolchains under `%LOCALAPPDATA%` / `%USERPROFILE%`) are not readable by default. Add them with `--ro`: for Python the folder that contains `python.exe` **and** the base prefix (`sys.base_prefix`; for a venv, both the venv and the base install). Python from the **Microsoft Store** lives under `WindowsApps` and will most likely not work.
* **Package managers and caches** (`pip`, `npm`, `cargo`) need a writable cache or `--rw` into a project-local one, and `--net`.
* **TLS stacks.** Tools that use Schannel / the Windows certificate store (`curl.exe`, some git builds, .NET) may need additional `--ro` paths or may fail; this is unverified.
* **Localhost is blocked** (see above).
* **No console.** The child gets pipes, not a console: progress bars, colour detection, `input()` and anything interactive behave differently. stdin is `NUL`.
* **Environment is filtered.** `USERPROFILE`, `HOME`, `APPDATA` and all API keys are dropped; pass what a tool really needs with `--env`. `TEMP` / `TMP` point to the container's own temp folder. `LOCALAPPDATA` is always set to the container's own folder (never your real profile): Windows 11 refuses to start a process in an AppContainer without it (error `0xCB`).
* **ACL cost.** Granting and revoking inheriting ACEs on a big tree (`node_modules`, large repos) can take a long time. Grant the smallest folder that works.
* **Protected or non-inheriting children.** Files/folders whose DACL has inheritance disabled will not receive the grant, so the command gets *Access denied* on them.
* **Not NTFS.** FAT/exFAT and some network shares have no ACLs; granting fails, so mshbox fails closed.
* **Background processes do not survive** the root process: the job is terminated when the root exits.
* **Crash recovery** runs automatically at the start of every `run` and via `mshbox cleanup`. It only repairs runs whose owner PID (checked together with its creation time, to survive PID reuse) is gone.
* **Journal location** is `%LOCALAPPDATA%\mshbox\journal` (override with `MSHBOX_HOME`). If you delete it before cleanup, orphan ACEs for a dead container SID can remain; they grant nothing to anyone, but they are visible in the folder's Security tab.

## Verification status

**Confirmed on one machine** (Windows 11, build 26200, Python 3.14, non-admin user) by `selftest` 7/7:
a container can be created and torn down; writes work inside `--rw` and fail outside it; a decoy secret is unreadable; the network is blocked by default and works with `--net`; a grandchild process is killed on timeout; ACEs, profile and journal are gone afterwards; a broken setup exits 125 without running the command. In the same runs, console programs (`cmd.exe`, a private `python.exe`) start with pipes and `CREATE_NO_WINDOW`, and `AssignProcessToJobObject` works on the suspended container process.

**Still unconfirmed** (written from documentation; most are tagged `# VERIFY:` in `mshbox.py`):

1. Behaviour on Windows 8 / 10 and on other Windows 11 builds.
2. `SetNamedSecurityInfoW` propagation details: that revoking also removes inherited copies on files the sandbox created, and that each object's inheritance state is left unchanged.
3. That `INTERNET_CLIENT_SID = S-1-15-3-1` is the `internetClient` capability on every build (it worked on the test machine).
4. Layout of the `TRUSTEE_W` / `EXPLICIT_ACCESS_W` ctypes structs on 32-bit Python.
5. The registry location the selftest uses for the profile-mapping check (the folder check is the primary signal).
6. Nested jobs when the host (an IDE, a CI runner) is already inside a job.
7. The HRESULT values treated as "profile already gone" in the delete-retry loop.
8. PID-reuse detection in `cleanup` after a real crash.
9. That world-readable folders carrying only an `Everyone` ACE are *not* readable from the container (the "secrets stay unreadable" claim assumes profile folders carry no ALL APPLICATION PACKAGES ACE, the default).
10. Tools beyond Python and `cmd.exe` (git, Node, `curl.exe`, .NET, package managers).

If you hit a case that is not covered here, please report the Windows build, the exact command and the output.

## Comparison with other tools

Public documentation as of late 2026; details change, so check upstream. This is a description of different trade-offs, not a ranking.

* **[Sandy](https://ahrvoje.github.io/sandy_cli/config.html)** is the closest relative: a Windows command-line sandbox with AppContainer, LPAC and restricted-token modes, a config file, deny-by-default grants and job-object limits. It is more configurable and covers more modes; mshbox is a single readable file with a built-in self-test, a crash-repair journal, and a Python API for embedding.
* **[Anthropic sandbox-runtime (`srt`)](https://github.com/anthropic-experimental/sandbox-runtime)** targets macOS, Linux and (alpha) Windows with domain-level network filtering through a proxy. Its Windows backend runs commands as a dedicated local user with a Windows Filtering Platform egress fence plus per-session ACEs, which needs a one-time elevated install. That buys more compatibility and finer network control; mshbox gives up both to avoid any elevation.
* **[OpenAI Codex's Windows sandbox](https://openai.com/index/building-codex-windows-sandbox/)** evaluated AppContainer and concluded it fit open-ended developer workflows poorly (shells, git, Python, package managers); they built write-restricted tokens with a synthetic SID, later an elevated design with dedicated users and firewall rules. mshbox makes the opposite bet: accept the compatibility cost (explicit `--ro` for tools, no localhost) in exchange for no admin rights and kernel-enforced network blocking. Their write-up also reports that applying workspace ACLs can be slow, which applies here too.

If you can accept a one-time elevated setup, or need broad tool compatibility, the tools above may suit you better.

## Integration with mshlite

A host that already spawns `cmd.exe /c script.bat` prepends the wrapper and switches to a relative `call` (an absolute batch path fails inside the container):

```python
import subprocess, sys

cmd = [sys.executable, "mshbox.py", "run", "--rw", PROJECT, "--cwd", PROJECT,
       "--timeout", "120", "--", "cmd.exe", "/d", "/c", "call", BAT_NAME]   # relative name, see "cmd.exe quirks"
proc = subprocess.run(cmd, capture_output=True)
if proc.returncode == 125:          # sandbox could not be built - the command did NOT run
    ...                             # ask the user; never silently re-run unsandboxed
```

Or, without a second Python process: `p = mshbox.run([...], PROJECT, rw=[PROJECT])`.
Treat exit code **125** as "not run" and **124** as "timed out".

## Tests

```bat
python -m unittest discover -s tests -v
```

* `tests/test_pure.py` - argument parsing, path normalisation, grant planning, secret-path refusal, command-line quoting (round-tripped through a reference `CommandLineToArgvW` parser), environment filtering, journal I/O. Any OS.
* `tests/test_orchestration.py` - the real startup / teardown / cleanup logic driven by a **fake** Win32 layer: journal written before any change, the command never spawned when any setup step fails, full rollback, idempotent teardown, tamper-resistant cleanup. Any OS. These prove the *logic*, not that Windows behaves like the fake.
* `tests/test_windows_integration.py` - real AppContainer runs, **skipped off Windows**. Run it on your machine; `selftest` is the authoritative check.

## License

MIT, see [LICENSE](LICENSE).
