"""Pure-logic tests. They run on ANY OS (Linux/macOS/Windows) and never touch Win32.

Run:  python -m unittest discover -s tests -v
"""
import contextlib
import io
import ntpath
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mshbox  # noqa: E402

HOME = "C:\\Users\\bob"
SYSDIRS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]


def parse_cmdline(s):
    """Reference parser for the MS C runtime / CommandLineToArgvW rules (arguments AFTER argv[0]).
    Used to prove that quote_arg() round-trips."""
    args, i, n = [], 0, len(s)
    while True:
        while i < n and s[i] in " \t":
            i += 1
        if i >= n:
            return args
        cur, inq = [], False
        while i < n:
            c = s[i]
            if c == "\\":
                j = i
                while j < n and s[j] == "\\":
                    j += 1
                k = j - i
                if j < n and s[j] == '"':
                    cur.append("\\" * (k // 2))
                    if k % 2:                      # odd: the quote is literal
                        cur.append('"')
                        i = j + 1
                    else:                          # even: the quote toggles quoting (handled next loop)
                        i = j
                else:
                    cur.append("\\" * k)
                    i = j
                continue
            if c == '"':
                inq = not inq
                i += 1
                continue
            if c in " \t" and not inq:
                break
            cur.append(c)
            i += 1
        args.append("".join(cur))


class QuotingTests(unittest.TestCase):
    TRICKY = ["abc", "a b", "", " ", '"', 'a"b', 'a\\"b', "C:\\dir\\", "C:\\my dir\\", "trailing\\\\",
              "\\\\server\\share", "tab\tx", "new\nline", '""', 'a b\\"c d\\\\', "x\\\\\\", '\\"', "--opt=a b"]

    def test_roundtrip_each_arg(self):
        for a in self.TRICKY:
            with self.subTest(arg=a):
                self.assertEqual(parse_cmdline(mshbox.quote_arg(a)), [a])

    def test_roundtrip_whole_line(self):
        line = " ".join(mshbox.quote_arg(a) for a in self.TRICKY)
        self.assertEqual(parse_cmdline(line), self.TRICKY)

    def test_plain_args_untouched(self):
        self.assertEqual(mshbox.quote_arg("script.py"), "script.py")
        self.assertEqual(mshbox.quote_arg("C:\\x\\y.exe"), "C:\\x\\y.exe")

    def test_empty_arg_is_quoted(self):
        self.assertEqual(mshbox.quote_arg(""), '""')

    def test_build_cmdline_plain(self):
        self.assertEqual(mshbox.build_cmdline(["python", "a b.py", "x"]), 'python "a b.py" x')

    def test_cmd_c_without_quotes_is_unchanged(self):
        self.assertEqual(mshbox.build_cmdline(["cmd.exe", "/c", "C:\\x.bat"]), "cmd.exe /c C:\\x.bat")

    def test_cmd_c_with_quotes_gets_outer_pair(self):
        self.assertEqual(mshbox.build_cmdline(["cmd.exe", "/c", "C:\\a b\\x.bat"]), 'cmd.exe /c ""C:\\a b\\x.bat""')
        self.assertEqual(mshbox.build_cmdline(["CMD", "/C", "C:\\a b\\x.bat", "arg 1"]),
                         'CMD /C ""C:\\a b\\x.bat" "arg 1""')

    def test_non_cmd_not_wrapped(self):
        self.assertEqual(mshbox.build_cmdline(["python.exe", "/c", "a b"]), 'python.exe /c "a b"')

    def test_wrap_batch(self):
        with mock.patch.dict(os.environ, {"COMSPEC": "C:\\Windows\\System32\\cmd.exe"}):
            self.assertEqual(mshbox.wrap_batch(["x.BAT", "a"]), ["C:\\Windows\\System32\\cmd.exe", "/c", "x.BAT", "a"])
            self.assertEqual(mshbox.wrap_batch(["run.cmd"])[1], "/c")
        self.assertEqual(mshbox.wrap_batch(["python", "x.py"]), ["python", "x.py"])


class PathTests(unittest.TestCase):
    def test_norm_path(self):
        self.assertEqual(mshbox.norm_path("C:\\Work\\..\\proj\\"), "C:\\proj")
        self.assertEqual(mshbox.norm_path("C:/a/b"), "C:\\a\\b")
        self.assertEqual(mshbox.norm_path("\\\\?\\C:\\x"), "C:\\x")

    def test_is_within(self):
        self.assertTrue(mshbox.is_within("C:\\Proj\\sub\\f.txt", "c:\\proj"))
        self.assertTrue(mshbox.is_within("C:\\proj", "C:\\proj\\"))
        self.assertFalse(mshbox.is_within("C:\\proj2", "C:\\proj"))          # prefix but not a child
        self.assertFalse(mshbox.is_within("C:\\proj", "C:\\proj\\sub"))
        self.assertFalse(mshbox.is_within("D:\\proj", "C:\\proj"))

    def test_dotdot_cannot_escape(self):
        self.assertFalse(mshbox.is_within("C:\\proj\\..\\other", "C:\\proj"))


class ForbiddenGrantTests(unittest.TestCase):
    def bad(self, p):
        return mshbox.forbidden_grant(p, HOME)

    def test_refused(self):
        for p in ("C:\\", "C:\\Users", HOME, HOME + "\\.ssh", HOME + "\\.ssh\\keys", HOME + "\\.aws",
                  HOME + "\\.mshlite\\cfg", HOME + "\\AppData\\Local", HOME + "\\AppData\\Roaming\\Mozilla\\Firefox",
                  HOME + "\\AppData\\Local\\Google", "\\\\srv\\share"):
            with self.subTest(path=p):
                self.assertIsNotNone(self.bad(p))

    def test_allowed(self):
        for p in ("C:\\work\\proj", HOME + "\\Documents\\proj", HOME + "\\AppData\\Local\\Programs\\Python\\Python311",
                  "D:\\code"):
            with self.subTest(path=p):
                self.assertIsNone(self.bad(p))

    def test_case_insensitive(self):
        self.assertIsNotNone(self.bad(HOME.upper() + "\\.SSH"))


class PlanGrantsTests(unittest.TestCase):
    PY = HOME + "\\AppData\\Local\\Programs\\Python\\Python311"

    def plan(self, rw=(), ro=(), exe_dir="C:\\Windows\\System32", cwd="C:\\work\\proj", exists=lambda p: True):
        return mshbox.plan_grants(rw, ro, exe_dir, cwd, HOME, SYSDIRS, lambda p: True, exists)

    def test_basic(self):
        g = self.plan(rw=["C:\\work\\proj"], ro=[self.PY], exe_dir=self.PY)
        got = sorted((x["path"], x["mask"]) for x in g)
        self.assertEqual(got, sorted([("C:\\work\\proj", mshbox.MASK_RW), (self.PY, mshbox.MASK_RO)]))
        self.assertTrue(all(x["dir"] for x in g))

    def test_system_dirs_not_granted(self):
        g = self.plan(rw=["C:\\work\\proj"], exe_dir="C:\\Windows\\System32")
        self.assertEqual([x["path"] for x in g], ["C:\\work\\proj"])

    def test_ro_inside_rw_is_dropped(self):
        g = self.plan(rw=["C:\\work\\proj"], ro=["C:\\work\\proj\\vendor"])
        self.assertEqual([x["path"] for x in g], ["C:\\work\\proj"])

    def test_rw_inside_ro_is_kept(self):
        g = self.plan(rw=["C:\\work\\proj\\out"], ro=["C:\\work\\proj"], cwd="C:\\work\\proj")
        self.assertEqual(sorted(x["mask"] for x in g), sorted([mshbox.MASK_RO, mshbox.MASK_RW]))

    def test_duplicates_collapse(self):
        g = self.plan(rw=["C:\\work\\proj", "c:\\WORK\\proj\\"])
        self.assertEqual(len(g), 1)

    def test_exe_dir_inside_rw(self):
        g = self.plan(rw=["C:\\work\\proj"], exe_dir="C:\\work\\proj")
        self.assertEqual([(x["path"], x["mask"]) for x in g], [("C:\\work\\proj", mshbox.MASK_RW)])

    def test_missing_path_fails_closed(self):
        with self.assertRaises(mshbox.SandboxError):
            self.plan(rw=["C:\\work\\proj"], exists=lambda p: False)

    def test_secret_grant_refused(self):
        for p in (HOME + "\\.ssh", HOME, "C:\\", HOME + "\\AppData\\Local"):
            with self.subTest(path=p), self.assertRaisesRegex(mshbox.SandboxError, "refusing"):
                self.plan(rw=[p], cwd=p)

    def test_cwd_must_be_covered(self):
        with self.assertRaisesRegex(mshbox.SandboxError, "--cwd"):
            self.plan(rw=["C:\\work\\proj"], cwd="C:\\elsewhere")

    def test_cwd_in_system_dir_is_ok(self):
        g = self.plan(rw=["C:\\work\\proj"], cwd="C:\\Windows\\Temp")
        self.assertEqual(len(g), 1)


class EnvTests(unittest.TestCase):
    def test_secrets_dropped_and_temp_forced(self):
        parent = {"Path": "C:\\x", "API_KEY": "sekrit", "SystemRoot": "C:\\Windows", "TEMP": "C:\\real\\temp",
                  "AWS_SECRET_ACCESS_KEY": "zzz", "USERPROFILE": HOME}
        env = mshbox.build_env(parent, {"FOO": "1"}, "C:\\ac\\tmp")
        self.assertEqual(env["TEMP"], "C:\\ac\\tmp")
        self.assertEqual(env["TMP"], "C:\\ac\\tmp")
        self.assertEqual(env["FOO"], "1")
        self.assertIn("Path", env)
        self.assertIn("SystemRoot", env)
        for k in ("API_KEY", "AWS_SECRET_ACCESS_KEY", "USERPROFILE"):
            self.assertNotIn(k, env)

    def test_explicit_env_overrides(self):
        env = mshbox.build_env({"PATH": "a"}, {"PATH": "b"}, "t")
        self.assertEqual(env["PATH"], "b")

    def test_env_block_format(self):
        blob = mshbox.env_block({"b": "2", "A": "1", "c": "3"})
        text = blob.decode("utf-16-le")
        self.assertEqual(text, "A=1\0b=2\0c=3\0\0")          # sorted case-insensitively, double-NUL terminated


class ResolveExeTests(unittest.TestCase):
    def test_found(self):
        with mock.patch.object(mshbox.shutil, "which", return_value="C:\\Python311\\python.exe"):
            exe, argv = mshbox.resolve_exe(["python", "x.py"], "C:\\work", "C:\\Python311")
        self.assertEqual(exe, "C:\\Python311\\python.exe")
        self.assertEqual(argv, ["python", "x.py"])

    def test_not_found_fails_closed(self):
        with mock.patch.object(mshbox.shutil, "which", return_value=None):
            with self.assertRaises(mshbox.SandboxError):
                mshbox.resolve_exe(["nope"], "C:\\work", "C:\\x")

    def test_batch_is_wrapped(self):
        with mock.patch.dict(os.environ, {"COMSPEC": "C:\\Windows\\System32\\cmd.exe"}), \
                mock.patch.object(mshbox.shutil, "which", return_value="C:\\Windows\\System32\\cmd.exe"):
            exe, argv = mshbox.resolve_exe(["run.bat"], "C:\\work", "")
        self.assertEqual(argv[:2], ["C:\\Windows\\System32\\cmd.exe", "/c"])
        self.assertEqual(exe, "C:\\Windows\\System32\\cmd.exe")


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.j = mshbox.Journal(os.path.join(self.tmp.name, "journal"))

    def rec(self, rid="abc123"):
        return {"version": 1, "run_id": rid, "name": "mshbox." + rid, "sid": "S-1-15-2-1-2-3-4-5-6-7",
                "owner_pid": 42, "owner_start": 99, "grants": [{"path": "C:\\p", "mask": 1, "dir": True}]}

    def test_roundtrip(self):
        self.j.write(self.rec())
        out = self.j.read_all()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][1]["grants"][0]["path"], "C:\\p")

    def test_overwrite_is_atomic_and_leaves_no_tmp(self):
        self.j.write(self.rec())
        r = self.rec()
        r["owner_pid"] = 7
        self.j.write(r)
        self.assertEqual(sorted(os.listdir(self.j.dir)), ["abc123.json"])
        self.assertEqual(self.j.read_all()[0][1]["owner_pid"], 7)

    def test_corrupt_and_incomplete_are_skipped(self):
        self.j.write(self.rec("good"))
        with open(os.path.join(self.j.dir, "bad.json"), "w") as f:
            f.write("{not json")
        with open(os.path.join(self.j.dir, "partial.json"), "w") as f:
            f.write('{"run_id": "x"}')
        with open(os.path.join(self.j.dir, "half.json.tmp"), "w") as f:
            f.write("{}")
        with contextlib.redirect_stderr(io.StringIO()):
            out = self.j.read_all()
        self.assertEqual([r["run_id"] for _, r in out], ["good"])

    def test_remove_is_idempotent(self):
        self.j.write(self.rec())
        self.j.remove("abc123")
        self.j.remove("abc123")
        self.assertEqual(self.j.read_all(), [])

    def test_missing_dir_reads_empty(self):
        self.assertEqual(self.j.read_all(), [])

    def test_mshbox_home_override(self):
        with mock.patch.dict(os.environ, {"MSHBOX_HOME": self.tmp.name}):
            self.assertEqual(mshbox.Journal().dir, os.path.join(self.tmp.name, "journal"))


class CliTests(unittest.TestCase):
    def parse(self, args):
        return mshbox.build_parser().parse_args(args)

    def exits(self, args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            self.parse(args)
        return cm.exception.code, err.getvalue()

    def test_split_command(self):
        self.assertEqual(mshbox.split_command(["run", "--net", "--", "a", "--", "b"]), (["run", "--net"], ["a", "--", "b"]))
        self.assertEqual(mshbox.split_command(["selftest"]), (["selftest"], []))

    def test_run_options(self):
        ns = self.parse(["run", "--rw", "a", "--rw", "b", "--ro", "c", "--net", "--timeout", "2.5", "--mem", "512",
                         "--procs", "8", "--cwd", "d", "--env", "K=V=W"])
        self.assertEqual((ns.rw, ns.ro, ns.net, ns.timeout, ns.mem, ns.procs, ns.cwd),
                         (["a", "b"], ["c"], True, 2.5, 512, 8, "d"))
        self.assertEqual(ns.env, [("K", "V=W")])

    def test_defaults(self):
        ns = self.parse(["run"])
        self.assertEqual((ns.rw, ns.ro, ns.net, ns.timeout, ns.mem, ns.procs), ([], [], False, None, None, None))

    def test_usage_errors_exit_125(self):
        for bad in (["run", "--mem", "0"], ["run", "--procs", "-1"], ["run", "--env", "NOEQUALS"], ["run", "--env", "=x"],
                    ["run", "--timeout", "abc"], ["bogus"], ["run", "--nope"]):
            with self.subTest(args=bad):
                code, _ = self.exits(bad)
                self.assertEqual(code, mshbox.EXIT_SETUP)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            self.parse(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(mshbox.__version__, out.getvalue())

    def test_main_requires_subcommand_and_command(self):
        for argv in ([], ["run"], ["run", "--rw", "x"], ["selftest", "--", "x"], ["cleanup", "--", "x"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                mshbox.main(argv)
            self.assertEqual(cm.exception.code, mshbox.EXIT_SETUP)

    def test_exit_code_constants(self):
        self.assertEqual((mshbox.EXIT_TIMEOUT, mshbox.EXIT_SETUP), (124, 125))


class FakeProc:
    def __init__(self, rc=7, timed_out=False):
        self.stdout, self.stderr = io.BytesIO(b"out-data"), io.BytesIO(b"err-data")
        self.returncode, self.timed_out, self.killed = rc, timed_out, False

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True


class CmdRunTests(unittest.TestCase):
    def ns(self, argv):
        head, command = mshbox.split_command(argv)
        return mshbox.build_parser().parse_args(head), command

    def run_cmd(self, proc=None, exc=None, argv=("run", "--", "x.exe")):
        ns, command = self.ns(list(argv))
        out, err = io.TextIOWrapper(io.BytesIO()), io.TextIOWrapper(io.BytesIO())
        launch = mock.Mock(side_effect=exc) if exc else mock.Mock(return_value=proc)
        with mock.patch.object(mshbox, "launch", launch), mock.patch.object(mshbox, "cleanup", return_value=(0, 0, 0)), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            rc = mshbox.cmd_run(ns, command)
            out.flush(), err.flush()
            return rc, out.buffer.getvalue(), err.buffer.getvalue(), launch

    def test_setup_failure_is_125_and_message(self):
        rc, _, err, launch = self.run_cmd(exc=mshbox.SandboxError("boom"))
        self.assertEqual(rc, 125)
        self.assertIn(b"NOT run", err)
        self.assertIn(b"boom", err)
        launch.assert_called_once()

    def test_any_exception_is_125(self):
        rc, *_ = self.run_cmd(exc=RuntimeError("weird"))
        self.assertEqual(rc, 125)

    def test_passthrough_and_exit_code(self):
        rc, out, err, _ = self.run_cmd(proc=FakeProc(rc=7))
        self.assertEqual((rc, out), (7, b"out-data"))
        self.assertIn(b"err-data", err)

    def test_timeout_is_124(self):
        rc, *_ = self.run_cmd(proc=FakeProc(rc=124, timed_out=True), argv=("run", "--timeout", "1", "--", "x.exe"))
        self.assertEqual(rc, 124)

    def test_cleanup_failure_never_blocks_run(self):
        ns, command = self.ns(["run", "--", "x.exe"])
        out, err = io.TextIOWrapper(io.BytesIO()), io.TextIOWrapper(io.BytesIO())
        with mock.patch.object(mshbox, "launch", return_value=FakeProc(rc=0)), \
                mock.patch.object(mshbox, "cleanup", side_effect=RuntimeError("sweep exploded")), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            self.assertEqual(mshbox.cmd_run(ns, command), 0)


class NonWindowsTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "only meaningful off Windows")
    def test_win32_refuses_off_windows(self):
        with self.assertRaises(mshbox.SandboxError):
            mshbox.Win32()


if __name__ == "__main__":
    unittest.main()
