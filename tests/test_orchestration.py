"""Orchestration tests: the real SandboxProcess / launch() / cleanup() logic driven by a FAKE Win32 layer.

They prove ordering and fail-closed behaviour (journal before any change, command never spawned when a
setup step fails, everything rolled back). They do NOT prove that Windows behaves as the fake does.
Run on any OS:  python -m unittest discover -s tests -v
"""
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mshbox  # noqa: E402

SID = "S-1-15-2-1-2-3-4-5-6-7"
HOME = "C:\\Users\\bob"


class FakeWin32:
    """Records every call. `fail` = {method_name: True} makes that method raise SandboxError."""

    def __init__(self, journal, fail=None, wait_results=(0,), exit_code=0, alive=False):
        self.journal, self.fail, self.calls = journal, fail or {}, []
        self.wait_results, self.exit, self.alive = list(wait_results), exit_code, alive
        self.journal_files_at_profile = None
        self._h = 100

    def _c(self, name, *args):
        self.calls.append((name,) + args)
        if self.fail.get(name):
            raise mshbox.SandboxError("injected failure in " + name)

    def names(self):
        return [c[0] for c in self.calls]

    def _handle(self):
        self._h += 1
        return self._h

    # --- identity / profile ---
    def derive_container_sid(self, name):
        self._c("derive_container_sid", name)
        return SID

    def process_start(self, pid):
        self._c("process_start", pid)
        return 12345

    def create_profile(self, name):
        self._c("create_profile", name)
        self.journal_files_at_profile = os.listdir(self.journal.dir) if os.path.isdir(self.journal.dir) else []
        return SID

    def container_folder(self, sid):
        self._c("container_folder", sid)
        return "C:\\ac\\folder"

    def ensure_temp(self, folder):
        self._c("ensure_temp", folder)
        return folder + "\\AC\\Temp"

    def delete_profile(self, name):
        self._c("delete_profile", name)

    # --- ACLs ---
    def add_ace(self, path, sid, mask, inherit):
        self._c("add_ace", path, sid, mask, inherit)

    def remove_aces(self, path, sid):
        self._c("remove_aces", path, sid)

    # --- job / process ---
    def create_job(self, mem, procs):
        self._c("create_job", mem, procs)
        return self._handle()

    def open_nul(self):
        self._c("open_nul")
        return self._handle()

    def pipe(self):
        self._c("pipe")
        return self._handle(), self._handle()

    def spawn(self, app, cmdline, cwd, envblock, sid, net, std):
        self._c("spawn", app, cmdline, cwd, envblock, sid, net, std)
        return self._handle(), self._handle(), 4242

    def assign_and_resume(self, job, hproc, hthread):
        self._c("assign_and_resume", job, hproc, hthread)

    def close(self, h):
        if h:
            self.calls.append(("close", h))

    def to_file(self, h):
        return io.BytesIO(b"")

    def wait_process(self, h, ms):
        self.calls.append(("wait_process", h, ms))
        return self.wait_results.pop(0) if len(self.wait_results) > 1 else self.wait_results[0]

    def exit_code(self, h):
        return self.exit

    def terminate_job(self, job):
        self._c("terminate_job", job)

    def terminate_process(self, h):
        self._c("terminate_process", h)

    def process_alive(self, pid, start=None):
        self.calls.append(("process_alive", pid, start))
        return self.alive


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = mshbox.Journal(os.path.join(self.tmp.name, "journal"))
        env = {"SystemRoot": "C:\\Windows", "ProgramFiles": "C:\\Program Files", "COMSPEC": "C:\\Windows\\System32\\cmd.exe"}
        patches = [mock.patch.dict(os.environ, env),
                   mock.patch.object(mshbox, "_isdir", lambda p: True),
                   mock.patch.object(mshbox, "_exists", lambda p: True),
                   mock.patch.object(mshbox.shutil, "which", return_value="C:\\Python311\\python.exe"),
                   mock.patch.object(mshbox.os.path, "expanduser", lambda p: HOME)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def launch(self, fake, **kw):
        args = dict(argv=["python", "x.py"], cwd="C:\\work\\proj", rw=["C:\\work\\proj"], ro=["C:\\Python311"])
        args.update(kw)
        with mock.patch.object(mshbox, "win32", return_value=fake):
            return mshbox.launch(journal=self.journal, **args)

    def fake(self, **kw):
        return FakeWin32(self.journal, **kw)


class HappyPathTests(Base):
    def test_order_and_cleanup(self):
        f = self.fake()
        p = self.launch(f)
        self.assertEqual(p.wait(5), 0)
        n = f.names()
        # strictly ordered setup
        for a, b in (("derive_container_sid", "process_start"), ("process_start", "create_profile"),
                     ("create_profile", "add_ace"), ("add_ace", "create_job"), ("create_job", "spawn"),
                     ("spawn", "assign_and_resume")):
            self.assertLess(n.index(a), n.index(b), "%s must come before %s" % (a, b))
        # journal existed BEFORE the profile was created
        self.assertEqual(len(f.journal_files_at_profile), 1)
        # teardown: every granted ACE removed, profile deleted, journal gone
        granted = [c[1] for c in f.calls if c[0] == "add_ace"]
        removed = [c[1] for c in f.calls if c[0] == "remove_aces"]
        self.assertEqual(sorted(granted), sorted(removed))
        self.assertEqual(len(granted), 2)
        self.assertIn("delete_profile", n)
        self.assertEqual(self.journal.read_all(), [])

    def test_ace_masks_and_no_dangerous_rights(self):
        f = self.fake()
        self.launch(f).wait(5)
        masks = {c[1]: c[3] for c in f.calls if c[0] == "add_ace"}
        self.assertEqual(masks["C:\\work\\proj"], mshbox.MASK_RW)
        self.assertEqual(masks["C:\\Python311"], mshbox.MASK_RO)
        WRITE_DAC, WRITE_OWNER, DELETE_CHILD = 0x40000, 0x80000, 0x40
        for m in masks.values():
            self.assertEqual(m & (WRITE_DAC | WRITE_OWNER | DELETE_CHILD), 0)

    def test_net_flag_reaches_spawn(self):
        for net in (False, True):
            f = self.fake()
            self.launch(f, net=net).wait(5)
            self.assertEqual([c for c in f.calls if c[0] == "spawn"][0][6], net)

    def test_job_limits_passed(self):
        f = self.fake()
        self.launch(f, mem_mb=256, procs=5).wait(5)
        self.assertIn(("create_job", 256, 5), f.calls)

    def test_exit_code_propagates(self):
        f = self.fake(exit_code=3)
        self.assertEqual(self.launch(f).wait(5), 3)

    def test_timeout_kills_job_and_returns_124(self):
        f = self.fake(wait_results=(0x102, 0))
        p = self.launch(f, timeout=1)
        self.assertEqual(p.wait(5), mshbox.EXIT_TIMEOUT)
        self.assertTrue(p.timed_out)
        self.assertIn("terminate_job", f.names())
        self.assertEqual(self.journal.read_all(), [])

    def test_env_is_filtered(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-secret", "Path": "C:\\x"}):
            f = self.fake()
            self.launch(f, env={"FOO": "bar"}).wait(5)
        blob = [c for c in f.calls if c[0] == "spawn"][0][4].decode("utf-16-le")
        self.assertNotIn("OPENAI_API_KEY", blob)
        self.assertIn("FOO=bar", blob)
        self.assertIn("TEMP=C:\\ac\\folder\\AC\\Temp", blob)

    def test_public_run_api(self):
        f = self.fake()
        with mock.patch.object(mshbox, "win32", return_value=f):
            p = mshbox.run(["python", "x.py"], "C:\\work\\proj", rw=["C:\\work\\proj"], ro=["C:\\Python311"],
                           journal=self.journal)
        for attr in ("stdout", "wait", "kill", "returncode", "poll"):
            self.assertTrue(hasattr(p, attr), attr)
        self.assertEqual(p.wait(5), 0)
        self.assertEqual(p.returncode, 0)


class FailClosedTests(Base):
    """Every setup failure => SandboxError, command NEVER spawned, everything rolled back."""

    def assert_clean(self, f):
        granted = [c[1] for c in f.calls if c[0] == "add_ace"]
        removed = [c[1] for c in f.calls if c[0] == "remove_aces"]
        self.assertEqual(sorted(granted), sorted(removed), "every attempted grant must be revoked")
        if "create_profile" in f.names() and not f.fail.get("create_profile"):
            self.assertIn("delete_profile", f.names())
        self.assertEqual(self.journal.read_all(), [], "journal must be removed after a clean rollback")

    def test_failure_at_each_early_step(self):
        for step in ("derive_container_sid", "process_start", "create_profile", "container_folder", "ensure_temp",
                     "add_ace", "create_job", "open_nul", "pipe", "spawn"):
            with self.subTest(step=step):
                self.setUp()
                f = self.fake(fail={step: True})
                with self.assertRaises(mshbox.SandboxError):
                    self.launch(f)
                if step != "spawn":
                    self.assertNotIn("spawn", f.names(), "command must not start when %s fails" % step)
                self.assertNotIn("assign_and_resume", f.names())
                self.assert_clean(f)

    def test_failure_when_job_assignment_fails_after_spawn(self):
        f = self.fake(fail={"assign_and_resume": True})
        with self.assertRaises(mshbox.SandboxError):
            self.launch(f)
        # the process was created SUSPENDED and must be killed, never resumed
        self.assertIn("terminate_process", f.names())
        self.assert_clean(f)

    def test_sid_mismatch_after_profile_creation(self):
        f = self.fake()
        f.create_profile = lambda name: (f._c("create_profile", name), "S-1-15-2-9-9-9-9-9-9-9")[1]
        with self.assertRaisesRegex(mshbox.SandboxError, "mismatch"):
            self.launch(f)
        self.assertNotIn("spawn", f.names())
        self.assertIn("delete_profile", f.names())

    def test_forbidden_path_fails_before_any_change(self):
        f = self.fake()
        with self.assertRaisesRegex(mshbox.SandboxError, "refusing"):
            self.launch(f, rw=[HOME + "\\.ssh"], cwd=HOME + "\\.ssh")
        self.assertEqual(f.calls, [], "nothing at all may be touched when validation fails")
        self.assertEqual(self.journal.read_all(), [])

    def test_missing_executable_fails_before_any_change(self):
        f = self.fake()
        with mock.patch.object(mshbox.shutil, "which", return_value=None):
            with self.assertRaises(mshbox.SandboxError):
                self.launch(f)
        self.assertEqual(f.calls, [])

    def test_nonexistent_cwd_fails_before_any_change(self):
        f = self.fake()
        with mock.patch.object(mshbox, "_isdir", lambda p: False):
            with self.assertRaises(mshbox.SandboxError):
                self.launch(f)
        self.assertEqual(f.calls, [])

    def test_empty_command(self):
        f = self.fake()
        with self.assertRaises(mshbox.SandboxError):
            self.launch(f, argv=[])
        self.assertNotIn("spawn", f.names())

    def test_failed_ace_removal_keeps_journal_for_cleanup(self):
        f = self.fake(fail={"remove_aces": True})
        with mock.patch.object(sys, "stderr", io.StringIO()) as err:   # patch BEFORE launch: the watcher starts at once
            p = self.launch(f)
            p.wait(5)
        self.assertEqual(len(self.journal.read_all()), 1, "journal must survive so `mshbox cleanup` can retry")
        self.assertIn("cleanup", err.getvalue())

    def test_partial_add_ace_is_revoked(self):
        f = self.fake()
        n = {"i": 0}
        orig = f.add_ace

        def flaky(path, sid, mask, inherit):
            n["i"] += 1
            if n["i"] == 2:
                f.calls.append(("add_ace", path, sid, mask, inherit))
                raise mshbox.SandboxError("second grant failed")
            orig(path, sid, mask, inherit)
        f.add_ace = flaky
        with self.assertRaises(mshbox.SandboxError):
            self.launch(f)
        self.assertNotIn("spawn", f.names())
        # the grant that FAILED half-way is also revoked (revoke is idempotent)
        self.assertEqual(len([c for c in f.calls if c[0] == "remove_aces"]), 2)


class ReleaseTests(Base):
    def test_release_is_idempotent(self):
        f = self.fake()
        p = self.launch(f)
        p.wait(5)
        before = len(f.calls)
        p._release()
        p._release()
        self.assertEqual(len(f.calls), before)

    def test_kill_terminates_job(self):
        f = self.fake(wait_results=(0x102, 0))
        p = self.launch(f)            # no timeout: watcher thread waits... fake returns 0x102 only once
        p.wait(5)
        self.assertIn("terminate_job", f.names())


class CleanupTests(Base):
    def write(self, rid="dead1", pid=999, sid=SID, name=None, grants=None):
        self.journal.write({"version": 1, "run_id": rid, "name": name or "mshbox." + rid, "sid": sid,
                            "owner_pid": pid, "owner_start": 5,
                            "grants": grants if grants is not None else [{"path": "C:\\a", "mask": 1, "dir": True},
                                                                         {"path": "C:\\b", "mask": 1, "dir": True}]})

    def test_dead_owner_is_repaired(self):
        self.write()
        f = self.fake(alive=False)
        self.assertEqual(mshbox.cleanup(self.journal, f, log=lambda m: None), (1, 0, 0))
        self.assertEqual(sorted(c[1] for c in f.calls if c[0] == "remove_aces"), ["C:\\a", "C:\\b"])
        self.assertIn(("delete_profile", "mshbox.dead1"), f.calls)
        self.assertEqual(self.journal.read_all(), [])

    def test_live_owner_is_never_touched(self):
        self.write()
        f = self.fake(alive=True)
        self.assertEqual(mshbox.cleanup(self.journal, f, log=lambda m: None), (0, 1, 0))
        self.assertEqual([c for c in f.calls if c[0] in ("remove_aces", "delete_profile")], [])
        self.assertEqual(len(self.journal.read_all()), 1)

    def test_failure_keeps_journal(self):
        self.write()
        f = self.fake(alive=False, fail={"delete_profile": True})
        self.assertEqual(mshbox.cleanup(self.journal, f, log=lambda m: None), (0, 0, 1))
        self.assertEqual(len(self.journal.read_all()), 1)

    def test_tampered_journal_is_refused(self):
        """A journal pointing at a non-AppContainer SID (e.g. 'Everyone') must never be acted on."""
        self.write(rid="evil", sid="S-1-1-0")
        self.write(rid="evil2", name="notmine")
        f = self.fake(alive=False)
        done, skipped, failed = mshbox.cleanup(self.journal, f, log=lambda m: None)
        self.assertEqual((done, failed), (0, 2))
        self.assertEqual([c for c in f.calls if c[0] in ("remove_aces", "delete_profile")], [])

    def test_missing_path_does_not_block_repair(self):
        self.write()
        f = self.fake(alive=False)
        with mock.patch.object(mshbox, "_exists", lambda p: p != "C:\\a"):
            self.assertEqual(mshbox.cleanup(self.journal, f, log=lambda m: None), (1, 0, 0))
        self.assertEqual([c[1] for c in f.calls if c[0] == "remove_aces"], ["C:\\b"])


if __name__ == "__main__":
    unittest.main()
