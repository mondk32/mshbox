"""Windows-only integration tests. SKIPPED on every other OS.

*** NOT YET RUN ON REAL WINDOWS BY THE AUTHOR. *** These are the first thing to run on a real machine:
    python -m unittest tests.test_windows_integration -v
They create only temp folders, and clean up after themselves. `python mshbox.py cleanup` repairs a crashed run.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
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

    def test_version(self):
        r = mshbox_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(b"mshbox", r.stdout)

    def test_setup_failure_exits_125_and_does_not_run(self):
        marker = os.path.join(self.ws, "ran.txt")
        bat = self.bat("a.bat", "echo x> ran.txt\r\n")
        r = mshbox_cli("run", "--rw", self.ws, "--rw", os.path.join(self.root, "does_not_exist"),
                       "--cwd", self.ws, "--", "cmd.exe", "/c", bat)
        self.assertEqual(r.returncode, 125, r.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_write_inside_rw(self):
        bat = self.bat("w.bat", "echo hi> inside.txt\r\n")
        r = mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--", "cmd.exe", "/c", bat)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.ws, "inside.txt")))

    def test_write_outside_rw_is_denied(self):
        target = os.path.join(self.outside, "pwn.txt")
        bat = self.bat("o.bat", 'echo ran> ran.txt\r\necho pwn> "%s"\r\n' % target)
        mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--", "cmd.exe", "/c", bat)
        self.assertTrue(os.path.isfile(os.path.join(self.ws, "ran.txt")), "script must have run for this test to mean anything")
        self.assertFalse(os.path.exists(target))

    def test_exit_code_is_passed_through(self):
        bat = self.bat("e.bat", "exit /b 7\r\n")
        r = mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--", "cmd.exe", "/c", bat)
        self.assertEqual(r.returncode, 7, r.stderr)

    def test_timeout_exits_124(self):
        bat = self.bat("t.bat", "ping -n 30 127.0.0.1 > nul\r\n")
        r = mshbox_cli("run", "--rw", self.ws, "--cwd", self.ws, "--timeout", "2", "--", "cmd.exe", "/c", bat)
        self.assertEqual(r.returncode, 124, r.stderr)

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
