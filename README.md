# mshbox

Run **one command** on Windows inside a per-run [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
with restricted filesystem and network access. No admin rights, no UAC prompt, no driver, no service,
no firewall rule, no compiled helper, **standard-library Python only** (ctypes + Win32).

> **Status: alpha, unaudited, and NOT yet run on real Windows by its author.**
> Everything that can be tested without Windows is tested (see [Tests](#tests)); everything that touches
> the Win32 API is written from documentation and is listed under
> [Needs verification on real Windows](#needs-verification-on-real-windows). Run `mshbox selftest`
> before you rely on it, and read [SECURITY.md](SECURITY.md).

mshbox was written as an optional wrapper for a terminal AI agent (`mshlite`) that runs shell commands
written by an LLM **on the user's own machine**. The goal is **damage control**: stop a mistaken or
prompt-injected command from writing outside the project, reading your secrets, or using the network.
It is **not** a boundary against deliberate malware.

## Quick start

```bat
python mshbox.py selftest
python mshbox.py run --rw C:\work\proj --ro C:\Python311 -- cmd.exe /c C:\work\proj\build.bat
python mshbox.py run --rw C:\work\proj --ro C:\Python311 --net --timeout 60 -- python tool.py
python mshbox.py cleanup
```

Requires Windows 8+ (AppContainer) and Python 3.8+. The repo is a single file, `mshbox.py`; copy it anywhere.

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

p = mshbox.run(["cmd.exe", "/c", r"C:\work\proj\build.bat"], r"C:\work\proj",
               rw=[r"C:\work\proj"], ro=[r"C:\Python311"], net=False, timeout=120)
for line in p.stdout:          # binary pipe (stderr merged unless merge_stderr=False)
    ...
code = p.wait()                # 124 on timeout; p.kill(), p.poll(), p.returncode, p.timed_out
```

`mshbox.run` raises `mshbox.SandboxError` if setup fails; in that case **nothing was started and nothing is left behind**.
Extra keyword arguments: `mem_mb`, `procs`, `env`, `merge_stderr`.

## Self-test

Run it on a real Windows machine **before trusting anything else**:

```bat
python mshbox.py selftest
python -m unittest tests.test_windows_integration -v
python -m unittest discover -s tests -v
```

`selftest` builds a temp workspace under `%TEMP%\mshbox_selftest_*` (it never touches real user files) and prints PASS / FAIL / SKIP for:

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
* **Environment is filtered.** `USERPROFILE`, `HOME`, `APPDATA` and all API keys are dropped; pass what a tool really needs with `--env`. `TEMP` / `TMP` point to the container's own temp folder.
* **ACL cost.** Granting and revoking inheriting ACEs on a big tree (`node_modules`, large repos) can take a long time. Grant the smallest folder that works.
* **Protected or non-inheriting children.** Files/folders whose DACL has inheritance disabled will not receive the grant, so the command gets *Access denied* on them.
* **Not NTFS.** FAT/exFAT and some network shares have no ACLs; granting fails, so mshbox fails closed.
* **Background processes do not survive** the root process: the job is terminated when the root exits.
* **Crash recovery** runs automatically at the start of every `run` and via `mshbox cleanup`. It only repairs runs whose owner PID (checked together with its creation time, to survive PID reuse) is gone.
* **Journal location** is `%LOCALAPPDATA%\mshbox\journal` (override with `MSHBOX_HOME`). If you delete it before cleanup, orphan ACEs for a dead container SID can remain; they grant nothing to anyone, but they are visible in the folder's Security tab.

## Needs verification on real Windows

Everything below was written from documentation, not from a running Windows machine. Each item is also tagged `# VERIFY:` in `mshbox.py` where applicable.

1. `SetNamedSecurityInfoW` propagation: that granting adds an inherited ACE to existing children, that revoking (`REVOKE_ACCESS`) also removes the inherited copies on files the sandbox created, and that the `PROTECTED` / `UNPROTECTED_DACL_SECURITY_INFORMATION` flag handling keeps each object's inheritance state unchanged.
2. `CreateProcessW` with `CREATE_NO_WINDOW` + redirected pipes + `STARTF_USESTDHANDLES` + an explicit handle list actually starts console programs (`cmd.exe`, `python.exe`) in an AppContainer.
3. Python starting inside the container with only `--ro <prefix>`: which extra paths/DLLs it needs.
4. `INTERNET_CLIENT_SID = S-1-15-3-1` is the `internetClient` capability SID.
5. Layout of `TRUSTEE_W` / `EXPLICIT_ACCESS_W` in the ctypes structs on 32- and 64-bit Python.
6. `GetAppContainerFolderPath` is exported by `userenv.dll` with signature `(PCWSTR sid, PWSTR *path)`.
7. The container temp path `<folder>\AC\Temp`, and that it exists or can be created.
8. The registry location used by the selftest to check that the profile mapping is gone (`HKCU\...\AppContainer\Mappings\<sid>`). The folder check is the primary signal.
9. `AssignProcessToJobObject` on a *suspended* AppContainer process, including when the host (for example an IDE or CI runner) is already inside a job (nested jobs need Windows 8+).
10. `DeleteAppContainerProfile` succeeding right after the last process exits (there is a retry loop; the HRESULT values treated as "already gone" are unverified).
11. `GetProcessTimes` / `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` PID-reuse detection in `cleanup`.
12. That `Everyone`-only world-readable folders are *not* readable from the container (the claim "secrets stay unreadable" assumes profile folders do not carry ALL APPLICATION PACKAGES ACEs - the default).

## Comparison with other tools

Public documentation as of late 2026; details change, so check upstream. This is a description of different trade-offs, not a ranking.

* **[Sandy](https://ahrvoje.github.io/sandy_cli/config.html)** is the closest relative: a Windows command-line sandbox with AppContainer, LPAC and restricted-token modes, a config file, deny-by-default grants and job-object limits. It is more configurable and covers more modes; mshbox is a single readable file with a built-in self-test, a crash-repair journal, and a Python API for embedding.
* **[Anthropic sandbox-runtime (`srt`)](https://github.com/anthropic-experimental/sandbox-runtime)** targets macOS, Linux and (alpha) Windows with domain-level network filtering through a proxy. Its Windows backend runs commands as a dedicated local user with a Windows Filtering Platform egress fence plus per-session ACEs, which needs a one-time elevated install. That buys more compatibility and finer network control; mshbox gives up both to avoid any elevation.
* **[OpenAI Codex's Windows sandbox](https://openai.com/index/building-codex-windows-sandbox/)** evaluated AppContainer and concluded it fit open-ended developer workflows poorly (shells, git, Python, package managers); they built write-restricted tokens with a synthetic SID, later an elevated design with dedicated users and firewall rules. mshbox makes the opposite bet: accept the compatibility cost (explicit `--ro` for tools, no localhost) in exchange for no admin rights and kernel-enforced network blocking. Their write-up also reports that applying workspace ACLs can be slow, which applies here too.

If you can accept a one-time elevated setup, or need broad tool compatibility, the tools above may suit you better.

## Integration with mshlite

A host that already spawns `cmd.exe /c script.bat` only needs to prepend the wrapper:

```python
import subprocess, sys

cmd = [sys.executable, "mshbox.py", "run", "--rw", PROJECT, "--ro", PYTHON_DIR,
       "--timeout", "120", "--", "cmd.exe", "/c", BAT_FILE]
proc = subprocess.run(cmd, capture_output=True)
if proc.returncode == 125:          # sandbox could not be built - the command did NOT run
    ...                             # ask the user; never silently re-run unsandboxed
```

Or, without a second Python process: `p = mshbox.run([...], PROJECT, rw=[PROJECT], ro=[PYTHON_DIR])`.
Treat exit code **125** as "not run" and **124** as "timed out".

## Tests

```bat
python -m unittest discover -s tests -v
```

* `tests/test_pure.py` - argument parsing, path normalisation, grant planning, secret-path refusal, command-line quoting (round-tripped through a reference `CommandLineToArgvW` parser), environment filtering, journal I/O. Any OS.
* `tests/test_orchestration.py` - the real startup / teardown / cleanup logic driven by a **fake** Win32 layer: journal written before any change, the command never spawned when any setup step fails, full rollback, idempotent teardown, tamper-resistant cleanup. Any OS. These prove the *logic*, not that Windows behaves like the fake.
* `tests/test_windows_integration.py` - real AppContainer runs, **skipped off Windows**, not yet run by the author.

## License

MIT, see [LICENSE](LICENSE).
