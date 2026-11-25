"""Windows-only integration tests. SKIPPED on every other OS.

Run from the project folder:
    py -m unittest tests.test_windows_integration -v
They create only temp folders, and clean up after themselves. `py mshbox.py cleanup` repairs a crashed run.
Batch files are started as `cmd /d /c call name.bat` with a relative name: cmd.exe cannot run an absolute-path batch file
(or `dir`) inside an AppContainer because it touches the drive root. Long-running / interpreter tests use a private
runtime copy (mshbox.copy_runtime) because an all-users Python install cannot be shared with the container.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)
MSHBOX = os.path.join(ROOT, "mshbox.py")
ON_WINDOWS = os.name == "nt"


def mshbox_cli(*args, timeout=120):
    return subprocess.run([sys.executable, MSHBOX] + list(args), capture_output=True, timeout=timeout)


@unittest.skipUnless(ON_WINDOWS, "needs real Windows (AppContainer)")
class WindowsIntegration(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="mshbox_it_")
        self.ws = os.path.join(self.root, "ws")
        self.outside = os.path.join(self.root, "outside")
        os.makedirs(self.ws)
        os.makedirs(self.outside)
        self.addCleanup(shutil.rmtree, self.root, True)

    def bat(self, name, body):
        path = os.path.join(self.ws, name)
        with open(path, "w") as f:
            f.write("@echo off\r\n" + body)
        return path

    def run_bat(self, name, body, *extra):
        self.bat(name, body)
        return mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, *extra, "--", "cmd.exe", "/d", "/c", "call", name)

    def private_python(self):
        import mshbox
        return mshbox.copy_runtime(os.path.join(self.ws, "py"))

    def test_version(self):
        r = mshbox_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(b"mshbox", r.stdout)

    def test_setup_failure_exits_125_and_does_not_run(self):
        marker = os.path.join(self.ws, "ran.txt")
        self.bat("a.bat", "echo x> ran.txt\r\n")
        r = mshbox_cli("run", "--rw", self.ws, "--rw", os.path.join(self.root, "does_not_exist"),
                       "--cwd", self.ws, "--", "cmd.exe", "/d", "/c", "call", "a.bat")
        self.assertEqual(r.returncode, 125, r.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_write_inside_rw(self):
        r = self.run_bat("w.bat", "echo hi> inside.txt\r\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.ws, "inside.txt")))

    def test_write_outside_rw_is_denied(self):
        target = os.path.join(self.outside, "pwn.txt")
        self.run_bat("o.bat", 'echo ran> ran.txt\r\necho pwn> "%s"\r\n' % target)
        self.assertTrue(os.path.isfile(os.path.join(self.ws, "ran.txt")), "script must have run for this test to mean anything")
        self.assertFalse(os.path.exists(target))

    def test_exit_code_is_passed_through(self):
        r = self.run_bat("e.bat", "exit /b 7\r\n")
        self.assertEqual(r.returncode, 7, r.stderr)

    def test_timeout_exits_124(self):
        py = self.private_python()
        r = mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--timeout", "3", "--", py, "-I", "-c",
                       "import time; time.sleep(60)")
        self.assertEqual(r.returncode, 124, r.stderr)

    def test_private_python_runs_and_writes_inside_only(self):
        py = self.private_python()
        outside = os.path.join(self.outside, "evil.txt")
        script = os.path.join(self.ws, "t.py")
        with open(script, "w") as f:
            f.write("open('inside.txt','w').write('x'); print('START')\n"
                    "try:\n    open(%r,'w').write('x'); print('LEAK')\n"
                    "except OSError:\n    print('DENIED')\n" % outside)
        r = mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--", py, "-I", "t.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"START", r.stdout)
        self.assertIn(b"DENIED", r.stdout)
        self.assertNotIn(b"LEAK", r.stdout)
        self.assertTrue(os.path.isfile(os.path.join(self.ws, "inside.txt")))
        self.assertFalse(os.path.exists(outside))

    def test_no_leftovers_after_runs(self):
        self.run_bat("l.bat", "echo hi> l.txt\r\n")
        r = mshbox_cli("cleanup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"0 repaired", r.stdout)     # nothing was left for cleanup to repair

    def test_cleanup_with_nothing_to_do(self):
        r = mshbox_cli("cleanup")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_full_selftest(self):
        r = mshbox_cli("selftest", timeout=300)
        sys.stdout.write(r.stdout.decode("utf-8", "replace"))
        self.assertNotIn(b"[FAIL]", r.stdout)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
