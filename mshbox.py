#!/usr/bin/env python3
"""mshbox - run ONE command inside a Windows AppContainer with restricted files and network.

ALPHA, UNAUDITED. selftest passes on one real Windows 11 machine only. See README.md / SECURITY.md.

How it works (details in README):
  * a per-run AppContainer profile (no capabilities => no network; --net adds internetClient only)
  * additive, inheriting ACEs granted to that container SID on --rw / --ro paths (journalled first)
  * a Job Object (kill-on-close, optional memory / process limits) so the whole tree dies together
  * everything is undone in a `finally`; `mshbox cleanup` repairs after a crash
FAIL CLOSED: any setup problem => SandboxError => exit 125 and the command is never started.

Everything above the `Win32` class is pure logic and runs on any OS (unit-tested that way).
Lines marked `# VERIFY:` are things not yet confirmed beyond the one tested machine.
"""
import argparse
import atexit
import json
import ntpath
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types

__version__ = "0.1.0a2"
EXIT_TIMEOUT, EXIT_SETUP, EXIT_INTERRUPT = 124, 125, 130

# --- access masks (winnt.h). Deliberately NO WRITE_DAC, WRITE_OWNER or FILE_DELETE_CHILD. ---
FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, DELETE = 0x120089, 0x120116, 0x1200A0, 0x10000
MASK_RO = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE                                      # 0x1200A9
MASK_RW = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE         # 0x1301BF
INTERNET_CLIENT_SID = "S-1-15-3-1"   # VERIFY: well-known capability SID for internetClient

# Secrets we refuse to grant (relative to the user profile). A grant on the path itself, on anything
# inside it, or on any ANCESTOR (which would inherit down into it) is refused. AppContainer ignores
# DENY ACEs, so "never grant" is the only protection available.
SECRET_REL = (".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".config", ".mshlite",
              ".git-credentials", ".netrc", ".npmrc", r"AppData\Roaming\Mozilla",
              r"AppData\Roaming\Microsoft\Credentials", r"AppData\Roaming\Microsoft\Protect",
              r"AppData\Local\Google\Chrome", r"AppData\Local\Microsoft\Edge",
              r"AppData\Local\BraveSoftware", r"AppData\Local\Mozilla")
# Environment variables passed to the child (everything else, e.g. API keys, is dropped).
SAFE_ENV = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "SYSTEMDRIVE", "OS", "PROGRAMDATA",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "PROGRAMW6432", "COMMONPROGRAMFILES", "PYTHONUTF8", "PYTHONIOENCODING", "LANG"}


class SandboxError(Exception):
    """Any failure to build the sandbox. Callers must treat it as 'command NOT run'."""


# =============================== pure logic (portable) ===============================
def quote_arg(arg):
    """Quote one argument per the MS C runtime / CommandLineToArgvW rules."""
    if arg and not any(c in arg for c in ' \t\n\v"'):
        return arg
    out, bs = ['"'], 0
    for ch in arg:
        if ch == "\\":
            bs += 1
        elif ch == '"':
            out.append("\\" * (2 * bs + 1) + '"')   # backslashes before a quote are doubled, quote escaped
            bs = 0
        else:
            out.append("\\" * bs + ch)
            bs = 0
    out.append("\\" * (2 * bs) + '"')               # trailing backslashes must be doubled before the closing quote
    return "".join(out)


def build_cmdline(argv):
    """argv -> CreateProcess command line. `cmd /c ...` needs one extra pair of quotes when the tail
    contains quotes, because cmd strips the first and last quote of its /c tail (see `cmd /?`)."""
    parts = [quote_arg(a) for a in argv]
    if ntpath.basename(argv[0]).lower() in ("cmd", "cmd.exe"):
        for i, a in enumerate(argv[1:], 1):
            if a.lower() in ("/c", "/k"):
                tail = " ".join(parts[i + 1:])
                if '"' in tail:
                    return " ".join(parts[:i + 1]) + ' "' + tail + '"'
                break
            if not a.startswith("/"):
                break
    return " ".join(parts)


def wrap_batch(argv):
    """CreateProcess on a .bat/.cmd is implicit-cmd magic; be explicit instead."""
    if ntpath.splitext(argv[0])[1].lower() in (".bat", ".cmd"):
        return [os.environ.get("COMSPEC") or r"C:\Windows\System32\cmd.exe", "/c"] + list(argv)
    return list(argv)


def norm_path(p):
    p = ntpath.normpath(ntpath.abspath(p))
    if p.startswith("\\\\?\\") and not p.upper().startswith("\\\\?\\UNC"):
        p = p[4:]
    return p


def path_key(p):
    return ntpath.normcase(norm_path(p))


def is_within(child, parent):
    """True if child == parent or child is below parent (case-insensitive, separator-safe)."""
    c, p = path_key(child), path_key(parent)
    return c == p or c.startswith(p.rstrip("\\") + "\\")


def forbidden_grant(path, home):
    """Return a reason string if granting `path` would expose secrets or is absurdly broad."""
    if ntpath.splitdrive(norm_path(path))[1] in ("", "\\"):
        return "drive roots are never granted"
    if is_within(home, path):
        return "the user profile (or one of its parents) is never granted"
    for rel in SECRET_REL:
        secret = ntpath.join(home, rel)
        if is_within(path, secret) or is_within(secret, path):
            return "it is, contains, or sits inside a protected secret location (%s)" % secret
    return None


def system_dirs(env):
    """Dirs that normally carry a read ACE for ALL APPLICATION PACKAGES (so no grant is needed/possible)."""
    return [norm_path(env[k]) for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432") if env.get(k)]


def plan_grants(rw, ro, exe_dir, cwd, home, sysdirs, isdir=os.path.isdir, exists=os.path.exists):
    """Compute the minimal list of {'path','mask','dir'} grants. Raises SandboxError on anything unsafe."""
    want = [(norm_path(p), MASK_RW, "rw") for p in rw] + [(norm_path(p), MASK_RO, "ro") for p in ro]
    want.append((norm_path(exe_dir), MASK_RO, "executable folder"))
    out = []
    for path, mask, why in want:
        if not exists(path):
            raise SandboxError("%s path does not exist: %s" % (why, path))
        if mask == MASK_RO and any(is_within(path, s) for s in sysdirs):
            continue                                  # already readable by all app packages
        bad = forbidden_grant(path, home)
        if bad:
            raise SandboxError("refusing to grant %s (%s): %s" % (path, why, bad))
        out.append({"path": path, "mask": mask, "dir": bool(isdir(path))})
    keep = []
    for i, g in enumerate(out):                       # drop grants already covered by another one
        for j, o in enumerate(out):
            if i == j or not o["dir"] or not is_within(g["path"], o["path"]) or o["mask"] & g["mask"] != g["mask"]:
                continue
            if path_key(o["path"]) != path_key(g["path"]) or o["mask"] != g["mask"] or j < i:
                break
        else:
            keep.append(g)
    covered = any(g["dir"] and is_within(cwd, g["path"]) for g in keep) or any(is_within(cwd, s) for s in sysdirs)
    if not covered:
        raise SandboxError("--cwd %s must be inside an --rw/--ro path" % cwd)
    return keep


def build_env(parent, extra, temp_dir):
    env = {k: v for k, v in parent.items() if k.upper() in SAFE_ENV}
    env["TEMP"] = env["TMP"] = temp_dir               # the container's own writable temp
    # Windows 11 (build 26200 verified) refuses CreateProcessW into an AppContainer with ERROR_ENVVAR_NOT_FOUND (0xCB)
    # unless LOCALAPPDATA is present. Point it at the container's own folder (parent of its Temp), never the real profile.
    env["LOCALAPPDATA"] = ntpath.dirname(temp_dir) or temp_dir
    env.update(extra or {})
    return env


def env_block(env):
    """UTF-16 environment block; Windows wants it sorted case-insensitively by name."""
    items = sorted(env.items(), key=lambda kv: kv[0].upper())
    return ("".join("%s=%s\0" % kv for kv in items) + "\0").encode("utf-16-le")


def resolve_exe(argv, cwd, path_env):
    argv = wrap_batch(argv)
    a0 = argv[0]
    if ntpath.dirname(a0):
        found = shutil.which(a0 if ntpath.isabs(a0) else ntpath.join(cwd, a0))
    else:
        found = shutil.which(a0, path=path_env)
    if not found:
        raise SandboxError("executable not found: %s" % a0)
    return norm_path(found), argv


class Journal:
    """One JSON file per run, written BEFORE any ACL/profile change. Lives under %LOCALAPPDATA%\\mshbox,
    which is never granted to the container, so sandboxed code cannot edit it."""

    def __init__(self, directory=None):
        base = os.environ.get("MSHBOX_HOME") or os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "mshbox")
        self.dir = directory or os.path.join(base, "journal")

    def path(self, run_id):
        return os.path.join(self.dir, run_id + ".json")

    def write(self, rec):
        os.makedirs(self.dir, exist_ok=True)
        final = self.path(rec["run_id"])
        with open(final + ".tmp", "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(final + ".tmp", final)             # atomic: either the old state or the complete new one

    def read_all(self):
        out = []
        for n in sorted(os.listdir(self.dir)) if os.path.isdir(self.dir) else []:
            if not n.endswith(".json"):
                continue
            p = os.path.join(self.dir, n)
            try:
                with open(p, encoding="utf-8") as f:
                    rec = json.load(f)
                for k in ("run_id", "name", "sid", "owner_pid", "grants"):
                    rec[k]
                out.append((p, rec))
            except (OSError, ValueError, KeyError, TypeError):
                sys.stderr.write("mshbox: skipping unreadable journal %s\n" % p)
        return out

    def remove(self, run_id):
        try:
            os.remove(self.path(run_id))
        except FileNotFoundError:
            pass


# =============================== Win32 layer (Windows only) ===============================
def _structs(ct, wt):
    S, P, DW = ct.Structure, ct.c_void_p, wt.DWORD

    class SECURITY_ATTRIBUTES(S): _fields_ = [("nLength", DW), ("lpSecurityDescriptor", P), ("bInheritHandle", wt.BOOL)]
    class SID_AND_ATTRIBUTES(S): _fields_ = [("Sid", P), ("Attributes", DW)]
    class SECURITY_CAPABILITIES(S): _fields_ = [("AppContainerSid", P), ("Capabilities", ct.POINTER(SID_AND_ATTRIBUTES)),
                                                ("CapabilityCount", DW), ("Reserved", DW)]
    class TRUSTEE(S): _fields_ = [("pMultipleTrustee", P), ("MultipleTrusteeOperation", ct.c_int), ("TrusteeForm", ct.c_int),
                                  ("TrusteeType", ct.c_int), ("ptstrName", P)]   # VERIFY: layout of TRUSTEE_W
    class EXPLICIT_ACCESS(S): _fields_ = [("grfAccessPermissions", DW), ("grfAccessMode", ct.c_int),
                                          ("grfInheritance", DW), ("Trustee", TRUSTEE)]
    class ACL_SIZE_INFORMATION(S): _fields_ = [("AceCount", DW), ("AclBytesInUse", DW), ("AclBytesFree", DW)]
    class STARTUPINFOW(S): _fields_ = [("cb", DW), ("lpReserved", P), ("lpDesktop", P), ("lpTitle", P), ("dwX", DW), ("dwY", DW),
                                       ("dwXSize", DW), ("dwYSize", DW), ("dwXCountChars", DW), ("dwYCountChars", DW),
                                       ("dwFillAttribute", DW), ("dwFlags", DW), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                                       ("lpReserved2", P), ("hStdInput", P), ("hStdOutput", P), ("hStdError", P)]
    class STARTUPINFOEXW(S): _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", P)]
    class PROCESS_INFORMATION(S): _fields_ = [("hProcess", P), ("hThread", P), ("dwProcessId", DW), ("dwThreadId", DW)]
    class JOBOBJECT_BASIC_LIMIT_INFORMATION(S): _fields_ = [
        ("PerProcessUserTimeLimit", ct.c_int64), ("PerJobUserTimeLimit", ct.c_int64), ("LimitFlags", DW),
        ("MinimumWorkingSetSize", ct.c_size_t), ("MaximumWorkingSetSize", ct.c_size_t), ("ActiveProcessLimit", DW),
        ("Affinity", ct.c_size_t), ("PriorityClass", DW), ("SchedulingClass", DW)]
    class IO_COUNTERS(S): _fields_ = [(n, ct.c_uint64) for n in ("r_ops", "w_ops", "o_ops", "r_bytes", "w_bytes", "o_bytes")]
    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(S): _fields_ = [
        ("Basic", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("Io", IO_COUNTERS), ("ProcessMemoryLimit", ct.c_size_t),
        ("JobMemoryLimit", ct.c_size_t), ("PeakProcessMemoryUsed", ct.c_size_t), ("PeakJobMemoryUsed", ct.c_size_t)]
    return types.SimpleNamespace(**{k: v for k, v in locals().items() if isinstance(v, type) and issubclass(v, S) and v is not S})


class Win32:
    """Thin wrappers over documented Win32 calls. Every method raises SandboxError with a readable
    message on failure; SIDs cross this boundary as strings (S-1-15-2-...)."""

    def __init__(self):
        if os.name != "nt":
            raise SandboxError("mshbox only works on Windows")
        import ctypes
        from ctypes import wintypes as wt
        self.ct, self.wt = ct, _ = ctypes, wt
        self.T = _structs(ct, wt)
        k, a, u, o = (ct.WinDLL(n, use_last_error=True) for n in ("kernel32", "advapi32", "userenv", "ole32"))
        P, PP, D, B, W, H = ct.c_void_p, ct.POINTER(ct.c_void_p), wt.DWORD, wt.BOOL, wt.LPCWSTR, ct.c_long
        f = self.f = types.SimpleNamespace()

        def d(dll, name, res, *args):                 # declare restype + argtypes for EVERY function we use
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = res, list(args)
            setattr(f, name, fn)
        d(u, "DeriveAppContainerSidFromAppContainerName", H, W, PP)
        d(u, "CreateAppContainerProfile", H, W, W, W, P, D, PP)
        d(u, "DeleteAppContainerProfile", H, W)
        d(u, "GetAppContainerFolderPath", H, W, PP)    # VERIFY: lives in userenv.dll, (PCWSTR sid, PWSTR* path)
        d(o, "CoTaskMemFree", None, P)
        d(a, "ConvertSidToStringSidW", B, P, PP)
        d(a, "ConvertStringSidToSidW", B, W, PP)
        d(a, "FreeSid", P, P)
        d(a, "GetNamedSecurityInfoW", D, W, ct.c_int, D, P, P, PP, P, PP)
        d(a, "SetNamedSecurityInfoW", D, W, ct.c_int, D, P, P, P, P)
        d(a, "SetEntriesInAclW", D, ct.c_ulong, P, P, PP)
        d(a, "GetSecurityDescriptorControl", B, P, ct.POINTER(wt.WORD), ct.POINTER(D))
        d(a, "GetAclInformation", B, P, P, D, ct.c_int)
        d(a, "GetAce", B, P, D, PP)
        d(k, "LocalFree", P, P)
        d(k, "CloseHandle", B, P)
        d(k, "CreatePipe", B, PP, PP, P, D)
        d(k, "SetHandleInformation", B, P, D, D)
        d(k, "CreateFileW", P, W, D, D, P, D, D, P)
        d(k, "CreateJobObjectW", P, P, W)
        d(k, "SetInformationJobObject", B, P, ct.c_int, P, D)
        d(k, "AssignProcessToJobObject", B, P, P)
        d(k, "TerminateJobObject", B, P, ct.c_uint)
        d(k, "TerminateProcess", B, P, ct.c_uint)
        d(k, "InitializeProcThreadAttributeList", B, P, D, D, ct.POINTER(ct.c_size_t))
        d(k, "UpdateProcThreadAttribute", B, P, D, ct.c_size_t, P, ct.c_size_t, P, P)
        d(k, "DeleteProcThreadAttributeList", None, P)
        d(k, "CreateProcessW", B, W, wt.LPWSTR, P, P, B, D, P, W, P, P)
        d(k, "ResumeThread", D, P)
        d(k, "WaitForSingleObject", D, P, D)
        d(k, "GetExitCodeProcess", B, P, ct.POINTER(D))
        d(k, "OpenProcess", P, D, B, D)
        d(k, "GetProcessTimes", B, P, P, P, P, P)

    # ---- error helpers ----
    def _err(self, what, code=None):
        code = (self.ct.get_last_error() if code is None else code) & 0xFFFFFFFF
        shown = code & 0xFFFF if code >> 16 == 0x8007 else code    # HRESULT_FROM_WIN32 -> plain Win32 code
        return SandboxError("%s failed: 0x%08X %s" % (what, code, self.ct.FormatError(shown).strip()))

    def _ok(self, ok, what):
        if not ok:
            raise self._err(what)

    def _rc(self, rc, what):                           # for DWORD-returning security APIs and HRESULTs
        if rc != 0:
            raise self._err(what, rc)

    # ---- SIDs and AppContainer profile ----
    def sid_to_str(self, psid):
        buf = self.ct.c_void_p()
        self._ok(self.f.ConvertSidToStringSidW(psid, self.ct.byref(buf)), "ConvertSidToStringSid")
        try:
            return self.ct.wstring_at(buf.value)
        finally:
            self.f.LocalFree(buf)

    def str_to_sid(self, s):                           # caller must LocalFree the result
        p = self.ct.c_void_p()
        self._ok(self.f.ConvertStringSidToSidW(s, self.ct.byref(p)), "ConvertStringSidToSid(%s)" % s)
        return p

    def derive_container_sid(self, name):
        p = self.ct.c_void_p()
        self._rc(self.f.DeriveAppContainerSidFromAppContainerName(name, self.ct.byref(p)), "DeriveAppContainerSid")
        try:
            return self.sid_to_str(p)
        finally:
            self.f.FreeSid(p)

    def create_profile(self, name):
        p = self.ct.c_void_p()
        self._rc(self.f.CreateAppContainerProfile(name, "mshbox sandbox", "mshbox per-run sandbox profile",
                                                  None, 0, self.ct.byref(p)), "CreateAppContainerProfile")
        try:
            return self.sid_to_str(p)
        finally:
            self.f.FreeSid(p)

    def delete_profile(self, name):
        for attempt in range(6):                       # the container's processes may still be exiting
            hr = self.f.DeleteAppContainerProfile(name) & 0xFFFFFFFF
            if hr == 0 or hr in (0x80070490, 0x80070002):   # OK, or already gone (NOT_FOUND / FILE_NOT_FOUND)
                return
            time.sleep(0.2)
        raise self._err("DeleteAppContainerProfile(%s)" % name, hr)

    def container_folder(self, sid):
        p = self.ct.c_void_p()
        self._rc(self.f.GetAppContainerFolderPath(sid, self.ct.byref(p)), "GetAppContainerFolderPath")
        try:
            return self.ct.wstring_at(p.value)
        finally:
            self.f.CoTaskMemFree(p)

    def ensure_temp(self, folder):
        tmp = ntpath.join(folder, "AC", "Temp")       # VERIFY: created by the profile; we create it if missing
        try:
            os.makedirs(tmp, exist_ok=True)
        except OSError as e:
            raise SandboxError("cannot create container temp %s: %s" % (tmp, e))
        return tmp

    def profile_exists(self, name, sid):
        import winreg
        key = (r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings" + "\\" + sid)
        try:                                           # VERIFY: registry location of the profile mapping
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, key))
            return True
        except OSError:
            return False

    # ---- ACLs: additive grant / exact revoke of this run's (unique) SID ----
    def _get_dacl(self, path):
        ct, wt = self.ct, self.wt
        dacl, sd = ct.c_void_p(), ct.c_void_p()
        self._rc(self.f.GetNamedSecurityInfoW(path, 1, 4, None, None, ct.byref(dacl), None, ct.byref(sd)), "read DACL of %s" % path)
        ctrl, rev = wt.WORD(), wt.DWORD()
        if not self.f.GetSecurityDescriptorControl(sd, ct.byref(ctrl), ct.byref(rev)):
            err = self._err("GetSecurityDescriptorControl")
            self.f.LocalFree(sd)
            raise err
        if dacl.value is None:                         # NULL DACL == "everyone": adding an ACE would RESTRICT it
            self.f.LocalFree(sd)
            raise SandboxError("%s has a NULL DACL; refusing to touch it" % path)
        return dacl, sd, bool(ctrl.value & 0x1000)     # 0x1000 = SE_DACL_PROTECTED

    def _apply(self, path, mode, sid, mask, inherit):
        """mode 1 = GRANT_ACCESS (add), 4 = REVOKE_ACCESS (remove explicit ACEs of that trustee only)."""
        ct = self.ct
        dacl, sd, protected = self._get_dacl(path)
        psid, newacl = self.str_to_sid(sid), ct.c_void_p()
        try:
            ea = self.T.EXPLICIT_ACCESS()
            ea.grfAccessPermissions, ea.grfAccessMode = mask, mode
            ea.grfInheritance = 3 if inherit else 0    # SUB_CONTAINERS_AND_OBJECTS_INHERIT
            ea.Trustee.TrusteeForm, ea.Trustee.TrusteeType, ea.Trustee.ptstrName = 0, 0, psid.value  # TRUSTEE_IS_SID / UNKNOWN
            self._rc(self.f.SetEntriesInAclW(1, ct.byref(ea), dacl, ct.byref(newacl)), "SetEntriesInAcl(%s)" % path)
            # Keep the object's existing protected/unprotected state explicit so inheritance is not changed.
            flag = 0x80000000 if protected else 0x20000000   # VERIFY: propagation behaviour of SetNamedSecurityInfoW
            self._rc(self.f.SetNamedSecurityInfoW(path, 1, 4 | flag, None, None, newacl, None), "SetNamedSecurityInfo(%s)" % path)
        finally:
            for x in (newacl, psid, sd):
                if x.value:
                    self.f.LocalFree(x)

    def add_ace(self, path, sid, mask, inherit):
        self._apply(path, 1, sid, mask, inherit)

    def remove_aces(self, path, sid):
        self._apply(path, 4, sid, 0, False)

    def has_ace(self, path, sid):
        ct = self.ct
        dacl, sd, _ = self._get_dacl(path)
        try:
            info = self.T.ACL_SIZE_INFORMATION()
            self._ok(self.f.GetAclInformation(dacl, ct.byref(info), ct.sizeof(info), 2), "GetAclInformation")
            for i in range(info.AceCount):
                pace = ct.c_void_p()
                self._ok(self.f.GetAce(dacl, i, ct.byref(pace)), "GetAce")
                if ct.c_ubyte.from_address(pace.value).value in (0, 1):   # ACCESS_ALLOWED / DENIED: header(4)+mask(4)+SID
                    if self.sid_to_str(pace.value + 8) == sid:
                        return True
            return False
        finally:
            self.f.LocalFree(sd)

    # ---- job object, pipes, process ----
    def create_job(self, mem_mb, procs):
        ct = self.ct
        job = self.f.CreateJobObjectW(None, None)
        self._ok(job, "CreateJobObject")
        info, flags = self.T.JOBOBJECT_EXTENDED_LIMIT_INFORMATION(), 0x2000   # KILL_ON_JOB_CLOSE
        if mem_mb:
            flags |= 0x200                             # JOB_MEMORY
            info.JobMemoryLimit = int(mem_mb) << 20
        if procs:
            flags |= 0x8                               # ACTIVE_PROCESS
            info.Basic.ActiveProcessLimit = int(procs)
        info.Basic.LimitFlags = flags
        if not self.f.SetInformationJobObject(job, 9, ct.byref(info), ct.sizeof(info)):   # 9 = ExtendedLimitInformation
            err = self._err("SetInformationJobObject")
            self.f.CloseHandle(job)
            raise err
        return job

    def _sa(self):
        sa = self.T.SECURITY_ATTRIBUTES()
        sa.nLength, sa.bInheritHandle = self.ct.sizeof(sa), 1
        return sa

    def pipe(self):
        r, w = self.ct.c_void_p(), self.ct.c_void_p()
        self._ok(self.f.CreatePipe(self.ct.byref(r), self.ct.byref(w), self.ct.byref(self._sa()), 0), "CreatePipe")
        self.f.SetHandleInformation(r, 1, 0)           # parent's read end must not be inherited
        return r.value, w.value

    def open_nul(self):
        h = self.f.CreateFileW("NUL", 0x80000000, 3, self.ct.byref(self._sa()), 3, 0, None)
        self._ok(h not in (None, self.ct.c_void_p(-1).value), "open NUL")
        return h

    def to_file(self, h):
        import msvcrt
        return os.fdopen(msvcrt.open_osfhandle(h, os.O_RDONLY), "rb", 0)

    def close(self, h):
        if h:
            self.f.CloseHandle(h)

    def spawn(self, app, cmdline, cwd, envblock, sid, net, std):
        """CreateProcessW in the AppContainer, SUSPENDED. Returns (hProcess, hThread, pid)."""
        ct, T, f = self.ct, self.T, self.f
        psid = self.str_to_sid(sid)
        capsid = self.str_to_sid(INTERNET_CLIENT_SID) if net else None
        caps = (T.SID_AND_ATTRIBUTES * 1)()
        sc = T.SECURITY_CAPABILITIES()
        sc.AppContainerSid = psid.value
        if net:
            caps[0].Sid, caps[0].Attributes = capsid.value, 4          # SE_GROUP_ENABLED
            sc.Capabilities, sc.CapabilityCount = ct.cast(caps, ct.POINTER(T.SID_AND_ATTRIBUTES)), 1
        handles = list(dict.fromkeys(std))             # duplicates in the handle list => ERROR_INVALID_PARAMETER
        harr = (ct.c_void_p * len(handles))(*handles)
        size = ct.c_size_t(0)
        f.InitializeProcThreadAttributeList(None, 2, 0, ct.byref(size))   # sizing call; is expected to fail with 122
        if ct.get_last_error() != 122:
            raise self._err("InitializeProcThreadAttributeList(size)")
        attrs = ct.create_string_buffer(size.value)
        self._ok(f.InitializeProcThreadAttributeList(attrs, 2, 0, ct.byref(size)), "InitializeProcThreadAttributeList")
        try:
            self._ok(f.UpdateProcThreadAttribute(attrs, 0, 0x20009, ct.byref(sc), ct.sizeof(sc), None, None),
                     "UpdateProcThreadAttribute(SECURITY_CAPABILITIES)")
            self._ok(f.UpdateProcThreadAttribute(attrs, 0, 0x20002, harr, ct.sizeof(harr), None, None),
                     "UpdateProcThreadAttribute(HANDLE_LIST)")
            si = T.STARTUPINFOEXW()
            si.StartupInfo.cb = ct.sizeof(si)
            si.StartupInfo.dwFlags = 0x100             # STARTF_USESTDHANDLES
            si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = std
            si.lpAttributeList = ct.addressof(attrs)
            pi, cmd = T.PROCESS_INFORMATION(), ct.create_unicode_buffer(cmdline)
            env = None if envblock is None else ct.create_string_buffer(envblock, len(envblock) + 2)   # None only used by envprobe diagnostics
            # EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW
            flags = 0x80000 | 0x400 | 0x4 | 0x08000000   # VERIFY: console apps run fine with NO_WINDOW + pipes in an AppContainer
            self._ok(f.CreateProcessW(app, cmd, None, None, True, flags, env, cwd, ct.byref(si), ct.byref(pi)),
                     "CreateProcessW(%s)" % app)
            return pi.hProcess, pi.hThread, pi.dwProcessId
        finally:
            f.DeleteProcThreadAttributeList(attrs)
            for x in (psid, capsid):
                if x is not None:
                    f.LocalFree(x)

    def assign_and_resume(self, job, hproc, hthread):
        self._ok(self.f.AssignProcessToJobObject(job, hproc), "AssignProcessToJobObject")   # VERIFY: nested jobs need Win8+
        self._ok(self.f.ResumeThread(hthread) != 0xFFFFFFFF, "ResumeThread")

    def terminate_job(self, job):
        self._ok(self.f.TerminateJobObject(job, 1), "TerminateJobObject")

    def terminate_process(self, h):
        self.f.TerminateProcess(h, 1)

    def wait_process(self, h, ms):
        r = self.f.WaitForSingleObject(h, 0xFFFFFFFF if ms is None else ms)
        self._ok(r != 0xFFFFFFFF, "WaitForSingleObject")
        return r                                       # 0 = exited, 0x102 = timeout

    def exit_code(self, h):
        c = self.wt.DWORD()
        self._ok(self.f.GetExitCodeProcess(h, self.ct.byref(c)), "GetExitCodeProcess")
        return c.value

    def _start_time(self, h):
        ft = [self.wt.FILETIME() for _ in range(4)]
        self._ok(self.f.GetProcessTimes(h, *[self.ct.byref(x) for x in ft]), "GetProcessTimes")
        return (ft[0].dwHighDateTime << 32) | ft[0].dwLowDateTime

    def process_start(self, pid):
        h = self.f.OpenProcess(0x1000, False, pid)     # PROCESS_QUERY_LIMITED_INFORMATION
        self._ok(h, "OpenProcess(%d)" % pid)
        try:
            return self._start_time(h)
        finally:
            self.f.CloseHandle(h)

    def process_alive(self, pid, start=None):
        """False only when we are SURE the process is gone (pid reuse is detected via creation time)."""
        h = self.f.OpenProcess(0x1000, False, int(pid))
        if not h:
            return self.ct.get_last_error() != 87      # 87 = no such pid; anything else (e.g. denied) => assume alive
        try:
            if self.exit_code(h) != 259:               # STILL_ACTIVE
                return False
            return start is None or self._start_time(h) == start
        finally:
            self.f.CloseHandle(h)


_win32 = None


def win32():
    global _win32
    if _win32 is None:
        _win32 = Win32()
    return _win32


# =============================== orchestration ===============================
_exists, _isdir = os.path.exists, os.path.isdir      # indirection so tests can fake the filesystem


class SandboxProcess:
    """subprocess-like handle: .stdout (binary pipe), .stderr (None if merged), .pid, wait(), poll(),
    kill(), returncode, timed_out. ACEs/profile are removed automatically when the process ends."""

    def __init__(self, w, journal, argv):
        self.w, self.journal, self.argv = w, journal, list(argv)
        self.run_id = secrets.token_hex(8)
        self.name = "mshbox." + self.run_id            # <= 64 chars, allowed charset
        self.sid = self.folder = None
        self.granted, self.grants = [], []
        self.profile_created = self.journaled = False
        self.job = self.hproc = self.pid = None
        self.stdout = self.stderr = None
        self.returncode, self.timed_out = None, False
        self._raw_reads, self._released = [], False
        self._lock, self._done = threading.RLock(), threading.Event()

    # ---- startup: strictly ordered; any exception => full rollback and the command never ran ----
    def _start(self, argv, cwd, rw, ro, net, timeout, mem_mb, procs, extra_env, merge, cmdline=None):
        w = self.w
        cwd = norm_path(cwd)
        if not argv:
            raise SandboxError("empty command")
        if not _isdir(cwd):
            raise SandboxError("--cwd is not a directory: %s" % cwd)
        exe, argv = resolve_exe(argv, cwd, os.environ.get("PATH", ""))
        self.grants = plan_grants(rw, ro, ntpath.dirname(exe), cwd, os.path.expanduser("~"),
                                  system_dirs(os.environ), _isdir, _exists)
        self.sid = w.derive_container_sid(self.name)
        self.journal.write({"version": 1, "run_id": self.run_id, "name": self.name, "sid": self.sid,
                            "owner_pid": os.getpid(), "owner_start": w.process_start(os.getpid()),
                            "grants": self.grants, "created": time.time()})   # BEFORE any ACL/profile change
        self.journaled = True
        created_sid = w.create_profile(self.name)
        self.profile_created = True                    # set BEFORE the check: a mismatch must still delete the profile
        if created_sid != self.sid:
            raise SandboxError("AppContainer SID mismatch after profile creation")
        self.folder = w.container_folder(self.sid)
        temp = w.ensure_temp(self.folder)
        for g in self.grants:
            self.granted.append(g)                     # recorded first: revoke is idempotent, a half-done add is not
            w.add_ace(g["path"], self.sid, g["mask"], g["dir"])
        self.job = w.create_job(mem_mb, procs)
        envblock = env_block(build_env(os.environ, extra_env, temp))
        child_side = []
        try:
            nul = w.open_nul(); child_side.append(nul)
            r_out, w_out = w.pipe(); self._raw_reads.append(r_out); child_side.append(w_out)
            w_err = w_out
            if not merge:
                r_err, w_err = w.pipe(); self._raw_reads.append(r_err); child_side.append(w_err)
            self.hproc, hthread, self.pid = w.spawn(exe, cmdline or build_cmdline(argv), cwd, envblock, self.sid, net, (nul, w_out, w_err))
            child_side.append(hthread)
            w.assign_and_resume(self.job, self.hproc, hthread)   # suspended until it is inside the job
        finally:
            for h in child_side:
                w.close(h)                             # parent must drop its copies or readers never see EOF
        reads, self._raw_reads = self._raw_reads, []
        self.stdout = w.to_file(reads[0])
        self.stderr = None if merge else w.to_file(reads[1])
        atexit.register(self._release)
        threading.Thread(target=self._watch, args=(timeout,), daemon=True).start()

    def _watch(self, timeout):
        """Wait for exit/timeout, then ALWAYS tear down (kills stragglers, removes ACEs, deletes profile)."""
        w, rc = self.w, EXIT_SETUP
        try:
            r = w.wait_process(self.hproc, None if timeout is None else max(1, int(timeout * 1000)))
            if r == 0x102:                             # WAIT_TIMEOUT
                self.timed_out = True
                w.terminate_job(self.job)
                w.wait_process(self.hproc, 5000)
                rc = EXIT_TIMEOUT
            else:
                rc = w.exit_code(self.hproc)
        except Exception as e:
            sys.stderr.write("mshbox: watcher error: %s\n" % e)
        finally:
            self._release()
            self.returncode = rc
            self._done.set()

    def _release(self):
        """Idempotent teardown; safe to call from any failure point."""
        with self._lock:
            if self._released:
                return
            self._released, w, problems = True, self.w, []
            atexit.unregister(self._release)           # a long-lived host (an agent) must not pile up one callback per command
            for h in self._raw_reads:
                w.close(h)
            for fn, h in ((w.terminate_job, self.job), (w.terminate_process, self.hproc if self.job is None else None)):
                try:
                    if h:
                        fn(h)
                except Exception:
                    pass
            w.close(self.job), w.close(self.hproc)     # closing the job also kills the tree (KILL_ON_JOB_CLOSE)
            for g in self.granted:
                try:
                    w.remove_aces(g["path"], self.sid)
                except SandboxError as e:
                    if _exists(g["path"]):
                        problems.append(str(e))
            if self.profile_created:
                try:
                    w.delete_profile(self.name)
                except SandboxError as e:
                    problems.append(str(e))
            if problems:                               # keep the journal so `mshbox cleanup` can retry
                sys.stderr.write("mshbox: WARNING cleanup incomplete (run `mshbox cleanup`): %s\n" % "; ".join(problems))
            elif self.journaled:
                self.journal.remove(self.run_id)

    # ---- subprocess-like API ----
    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode

    def poll(self):
        return self.returncode if self._done.is_set() else None

    def kill(self):
        with self._lock:
            if not self._released and self.job:
                self.w.terminate_job(self.job)

    def communicate(self):
        out = self.stdout.read()
        self.wait()
        return out


def launch(argv, cwd, rw=(), ro=(), net=False, timeout=None, mem_mb=None, procs=None, env=None,
           merge_stderr=True, journal=None, cmdline=None):
    """Start argv in the sandbox or raise SandboxError (nothing is left behind, command not run).
    `cmdline`: optional RAW command line used verbatim instead of quoting argv with the C-runtime rules. argv[0] is still the
    executable (resolved and granted). Needed for `cmd.exe /c <text>` where cmd parses the text itself and `\\"` is not an escape."""
    p = SandboxProcess(win32(), journal or Journal(), argv)
    try:
        p._start(list(argv), cwd, rw, ro, net, timeout, mem_mb, procs, env, merge_stderr, cmdline)
    except BaseException as e:
        if p.hproc:
            try:
                p.w.terminate_process(p.hproc)
            except Exception:
                pass
        p._release()
        if isinstance(e, SandboxError):
            raise
        raise SandboxError("%s: %s" % (type(e).__name__, e))
    return p


def run(argv, cwd, rw=(), ro=(), net=False, timeout=None, **kw):
    """Public API for host programs: mshbox.run([...], cwd, rw=[...], ro=[...]) -> SandboxProcess."""
    return launch(argv, cwd, rw=rw, ro=ro, net=net, timeout=timeout, **kw)


def cleanup(journal=None, w=None, log=print):
    """Repair leftovers of DEAD runs (owner pid gone). Returns (repaired, skipped_alive, failed)."""
    w, journal = w or win32(), journal or Journal()
    done = skipped = failed = 0
    for _path, rec in journal.read_all():
        rid = rec["run_id"]
        if not (str(rec["sid"]).startswith("S-1-15-2-") and str(rec["name"]).startswith("mshbox.")):
            failed += 1
            log("refusing journal %s: unexpected SID/name" % rid)
            continue
        if w.process_alive(rec["owner_pid"], rec.get("owner_start")):
            skipped += 1
            log("skip %s: owner pid %s is still running" % (rid, rec["owner_pid"]))
            continue
        errs = []
        for g in rec["grants"]:
            if _exists(g["path"]):
                try:
                    w.remove_aces(g["path"], rec["sid"])
                except SandboxError as e:
                    errs.append(str(e))
        try:
            w.delete_profile(rec["name"])
        except SandboxError as e:
            errs.append(str(e))
        if errs:
            failed += 1
            log("could not fully repair %s: %s" % (rid, "; ".join(errs)))
        else:
            journal.remove(rid)
            done += 1
            log("repaired %s" % rid)
    return done, skipped, failed


_RUNTIME_SKIP = {"test", "tests", "idlelib", "site-packages", "turtledemo", "tkinter", "ensurepip", "lib2to3",
                 "pydoc_data", "__pycache__", "tcl", "Doc", "include", "libs", "Scripts", "Tools"}


def copy_runtime(dst, src=None):
    """Copy a minimal CPython runtime (exe, DLLs, stdlib) to dst; returns the new python.exe.
    Why: an all-users install (e.g. D:\\Python314) has files with inheritance-blocked ACLs owned by Administrators; a
    normal user cannot grant an AppContainer read access to them, so python.exe dies with 0xC0000022 inside the sandbox.
    A copy inside a folder the user owns inherits the grant."""
    src = src or sys.base_prefix
    exe = os.path.join(src, "python.exe")
    if not os.path.isfile(exe):
        raise SandboxError("python.exe not found in %s" % src)
    os.makedirs(dst, exist_ok=True)
    for dp, dns, fns in os.walk(src):
        rel = os.path.relpath(dp, src)
        dns[:] = [d for d in dns if d not in _RUNTIME_SKIP]
        if rel == ".":
            fns = [f for f in fns if f.lower().startswith(("python3", "python.", "vcruntime", "msvcp"))]
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for f in fns:
            shutil.copyfile(os.path.join(dp, f), os.path.join(dst, rel, f))
    return os.path.join(dst, "python.exe")


# =============================== selftest ===============================
PROBE = '''import sys, socket, subprocess, time
print("START", flush=True)
if sys.argv[1] == "net":
    try:
        socket.create_connection(("1.1.1.1", 443), 5).close(); print("CONNECTED", flush=True)
    except OSError as e:
        print("BLOCKED", e, flush=True)
else:
    c = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(120)"])
    open("child.pid", "w").write(str(c.pid))
    time.sleep(120)
'''


def selftest():
    try:
        w = win32()
    except SandboxError as e:
        print("mshbox selftest: %s" % e, file=sys.stderr)
        return EXIT_SETUP
    tag = secrets.token_hex(4)
    root = tempfile.mkdtemp(prefix="mshbox_selftest_")           # everything we touch lives here
    ws, outside = os.path.join(root, "ws"), os.path.join(root, "outside")
    decoy = os.path.join(root, "fakehome", ".ssh")
    for d in (ws, outside, decoy):
        os.makedirs(d)
    secret = "MSHBOX-SECRET-" + tag
    with open(os.path.join(decoy, "id_rsa"), "w") as f:
        f.write(secret)
    with open(os.path.join(ws, "probe.py"), "w") as f:
        f.write(PROBE)
    rt = []

    def pyexe():                                              # private runtime copy inside the workspace (lazy, once)
        if not rt:
            rt.append(copy_runtime(os.path.join(ws, "py")))
        return rt[0]
    procs, results = [], []

    def sandbox(argv, **kw):
        p = launch(argv, ws, rw=[ws], **kw)
        procs.append(p)
        out = p.stdout.read().decode("utf-8", "replace")
        p.wait()
        return p.returncode, out

    def bat(name, body):
        path = os.path.join(ws, name)
        with open(path, "w") as f:
            f.write("@echo off\r\n" + body)
        return ["cmd.exe", "/d", "/c", "call", name]   # relative + `call`: cmd.exe with an absolute .bat path (or `dir`) touches
        # the drive root, which an AppContainer cannot access

    def verdict(ok, detail=""):
        return ("PASS" if ok else "FAIL"), detail

    def t1():
        rc, out = sandbox(bat("t1.bat", "echo hello> ok.txt\r\ntype ok.txt\r\n"))
        return verdict(rc == 0 and os.path.isfile(os.path.join(ws, "ok.txt")) and "hello" in out, "rc=%s out=%r" % (rc, out.strip()[:200]))

    def t2():
        drive = os.environ.get("SystemDrive", "C:")
        targets = [os.path.join(os.path.expanduser("~"), "mshbox_pwn_%s.txt" % tag), drive + "\\mshbox_pwn_%s.txt" % tag,
                   os.path.join(outside, "pwn.txt")]
        sandbox(bat("t2.bat", "echo ran> ran2.txt\r\n" + "".join('echo pwn> "%s"\r\n' % t for t in targets)))
        leaked = [t for t in targets if os.path.exists(t)]
        for t in leaked:
            os.remove(t)
        if not os.path.isfile(os.path.join(ws, "ran2.txt")):
            return verdict(False, "script did not run inside the sandbox (test is meaningless)")
        return verdict(not leaked, "LEAKED: %s" % leaked if leaked else "")

    def t3():
        sandbox(bat("t3.bat", 'echo ran> ran3.txt\r\ntype "%s" > leak.txt 2>&1\r\n' % os.path.join(decoy, "id_rsa")))
        if not os.path.isfile(os.path.join(ws, "ran3.txt")):
            return verdict(False, "script did not run inside the sandbox (test is meaningless)")
        leak = os.path.join(ws, "leak.txt")
        text = open(leak, errors="replace").read() if os.path.exists(leak) else ""
        return verdict(secret not in text, "decoy secret was readable!" if secret in text else "")

    def t4():
        import socket
        try:
            socket.create_connection(("1.1.1.1", 443), 3).close()
        except OSError as e:
            return "SKIP", "host cannot reach 1.1.1.1:443 (offline?): %s" % e
        _, off = sandbox([pyexe(), "-I", "probe.py", "net"])
        _, on = sandbox([pyexe(), "-I", "probe.py", "net"], net=True)
        if "START" not in off or "START" not in on:
            return verdict(False, "probe python did not start in the sandbox: %r / %r" % (off[:150], on[:150]))
        return verdict("CONNECTED" not in off and "CONNECTED" in on, "default=%s, --net=%s" % (off.split()[-1:], on.split()[-1:]))

    def t5():
        p = launch([pyexe(), "-I", "probe.py", "spawn"], ws, rw=[ws], timeout=6)
        procs.append(p)
        p.stdout.read()
        p.wait()
        pidf = os.path.join(ws, "child.pid")
        if not os.path.isfile(pidf):
            return verdict(False, "rc=%s; probe never recorded a grandchild pid (python may not start in sandbox)" % p.returncode)
        pid = int(open(pidf).read())
        for _ in range(30):
            if not w.process_alive(pid):
                break
            time.sleep(0.1)
        return verdict(p.returncode == EXIT_TIMEOUT and not w.process_alive(pid), "rc=%s grandchild pid %s" % (p.returncode, pid))

    def t6():
        bad = []
        for p in procs:
            bad += ["ACE left on %s" % g["path"] for g in p.grants if _exists(g["path"]) and w.has_ace(g["path"], p.sid)]
            if os.path.isdir(p.folder) or w.profile_exists(p.name, p.sid):
                bad.append("profile %s still present" % p.name)
            if os.path.exists(p.journal.path(p.run_id)):
                bad.append("journal %s still present" % p.run_id)
        return verdict(procs and not bad, "; ".join(bad))

    def t7():
        marker = os.path.join(ws, "t7_ran.txt")
        cmd = bat("t7.bat", "echo ran> t7_ran.txt\r\n")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "run", "--rw", ws, "--rw", os.path.join(root, "nope"),
                            "--cwd", ws, "--"] + cmd, capture_output=True, timeout=60)
        return verdict(r.returncode == EXIT_SETUP and not os.path.exists(marker), "rc=%s" % r.returncode)

    names = [("write inside --rw succeeds", t1), ("write outside --rw fails", t2), ("decoy secret unreadable", t3),
             ("network blocked by default, allowed with --net", t4), ("grandchild killed on timeout", t5),
             ("ACEs + profile + journal gone after runs", t6), ("broken setup exits 125, command not run", t7)]
    try:
        for i, (name, fn) in enumerate(names, 1):
            try:
                status, detail = fn()
            except Exception as e:
                status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
            results.append(status)
            print("[%s] %d. %s%s" % (status, i, name, " - " + detail if detail else ""), flush=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("%d passed, %d failed, %d skipped" % (results.count("PASS"), results.count("FAIL"), results.count("SKIP")))
    return 1 if "FAIL" in results else 0


# =============================== CLI ===============================
class _Parser(argparse.ArgumentParser):
    def error(self, message):                          # usage errors also mean "command NOT run" => 125
        self.print_usage(sys.stderr)
        sys.stderr.write("mshbox: error: %s\n" % message)
        sys.exit(EXIT_SETUP)


def _env_pair(s):
    if "=" not in s or s.startswith("="):
        raise argparse.ArgumentTypeError("expected KEY=VAL, got %r" % s)
    k, v = s.split("=", 1)
    return k, v


def _pos(s):
    n = int(s)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def split_command(argv):
    """Split at the first `--`: (mshbox args, command)."""
    return (argv[:argv.index("--")], argv[argv.index("--") + 1:]) if "--" in argv else (argv, [])


def build_parser():
    p = _Parser(prog="mshbox", description="Run ONE command in a restricted Windows AppContainer (alpha).")
    p.add_argument("--version", action="version", version="mshbox " + __version__)
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="run COMMAND after `--`")
    r.add_argument("--rw", action="append", default=[], metavar="PATH", help="read/write/delete inside PATH")
    r.add_argument("--ro", action="append", default=[], metavar="PATH", help="read+execute PATH")
    r.add_argument("--net", action="store_true", help="allow outbound internet (internetClient); localhost stays blocked")
    r.add_argument("--timeout", type=float, metavar="SEC")
    r.add_argument("--mem", type=_pos, metavar="MB", help="job-wide memory limit")
    r.add_argument("--procs", type=_pos, metavar="N", help="max simultaneous processes (includes cmd.exe itself)")
    r.add_argument("--cwd", metavar="DIR")
    r.add_argument("--env", action="append", default=[], type=_env_pair, metavar="KEY=VAL")
    sub.add_parser("selftest", help="run the built-in checklist")
    sub.add_parser("cleanup", help="repair leftovers of crashed runs")
    return p


def _pump(src, dst):
    try:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            dst.flush()                                # unbuffered pass-through
    except (OSError, ValueError):
        pass


def cmd_run(ns, command):
    try:
        try:
            cleanup(log=lambda m: None)                # best-effort sweep of dead runs; never fatal
        except Exception:
            pass
        p = launch(command, ns.cwd or os.getcwd(), rw=ns.rw, ro=ns.ro, net=ns.net, timeout=ns.timeout,
                   mem_mb=ns.mem, procs=ns.procs, env=dict(ns.env), merge_stderr=False)
    except Exception as e:                             # fail closed: ANY error => command not run
        sys.stderr.write("mshbox: sandbox setup failed, command NOT run: %s\n" % e)
        return EXIT_SETUP
    pumps = [threading.Thread(target=_pump, args=(p.stdout, sys.stdout.buffer), daemon=True),
             threading.Thread(target=_pump, args=(p.stderr, sys.stderr.buffer), daemon=True)]
    for t in pumps:
        t.start()
    interrupted = False
    try:
        while True:                                    # short waits so Ctrl+C is delivered promptly
            try:
                p.wait(0.2)
                break
            except subprocess.TimeoutExpired:
                pass
    except KeyboardInterrupt:
        interrupted = True
        p.kill()
        p.wait(15)
    for t in pumps:
        t.join(5)
    if interrupted:
        sys.stderr.write("mshbox: interrupted, process tree killed\n")
        return EXIT_INTERRUPT
    if p.timed_out:
        sys.stderr.write("mshbox: timed out after %ss, process tree killed\n" % ns.timeout)
        return EXIT_TIMEOUT
    if p.returncode == 0xC0000022:                     # STATUS_ACCESS_DENIED while the image loaded
        sys.stderr.write("mshbox: hint: the program could not read its own files inside the sandbox. All-users installs "
                         "(e.g. a Python under D:\\Python314) cannot be shared with an AppContainer without admin rights; "
                         "run a copy of the program that lives in a folder you own and pass that folder with --ro/--rw.\n")
    return p.returncode


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    head, command = split_command(argv)
    parser = build_parser()
    ns = parser.parse_args(head)
    if ns.cmd is None:
        parser.error("a subcommand is required (run, selftest, cleanup)")
    if ns.cmd == "run":
        if not command:
            parser.error("missing COMMAND after `--`")
        return cmd_run(ns, command)
    if command:
        parser.error("unexpected arguments after `--`")
    if ns.cmd == "selftest":
        return selftest()
    try:
        done, skipped, failed = cleanup()
    except SandboxError as e:
        sys.stderr.write("mshbox: %s\n" % e)
        return EXIT_SETUP
    print("cleanup: %d repaired, %d skipped (owner alive), %d failed" % (done, skipped, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
