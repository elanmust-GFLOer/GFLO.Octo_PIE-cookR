"""Named controls for current workers; no frozen test is imported or changed."""
import json
import multiprocessing
import multiprocessing.process
import os
from pathlib import Path
import pickle
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from b23r6a.contracts import ExpiredDeadline, Unavailable
from b23r6a.process_lifecycle import OwnedSpawnPopen, OwnedSpawnContext
from b23r6a.workers import WorkerSupervisor


class ConcurrentAdapter:
    def __init__(self, barrier, entered):
        self.barrier, self.entered = barrier, entered

    def observe(self):
        with self.entered.get_lock():
            self.entered.value += 1
        self.barrier.wait(.25)
        return True


class SlowSideEffect:
    def __init__(self, path):
        self.path = path

    def observe(self):
        time.sleep(.2)
        Path(self.path).write_text('LATE')
        return True


class TrueAdapter:
    def observe(self):
        return True


def quiet_child():
    pass


class LifecycleSecurity(unittest.TestCase):
    def popen_fixture(self, pid):
        child = object.__new__(OwnedSpawnPopen)
        child._state_lock = threading.RLock()
        child.pid, child.returncode = pid, None
        return child

    def test_waitpid_and_cache_publication_have_one_owner(self):
        child = self.popen_fixture(999999)
        reaped, publish, owner_entered, second_waitpid = [threading.Event() for _ in range(4)]
        calls, values, errors = [], [], []

        def waitpid(pid, flags):
            calls.append((pid, flags))
            if len(calls) > 1:
                second_waitpid.set()
                raise ChildProcessError()
            reaped.set()
            if not publish.wait(1):
                raise RuntimeError('BARRIER_TIMEOUT')
            return pid, 0

        def peer():
            try:
                values.append(child.poll())
            except BaseException as error:
                errors.append(type(error).__name__)

        def owner():
            owner_entered.set()
            peer()

        threads = [threading.Thread(target=peer), threading.Thread(target=owner)]
        try:
            with patch('os.waitpid', waitpid):
                threads[0].start()
                self.assertTrue(reaped.wait(1))
                threads[1].start()
                self.assertTrue(owner_entered.wait(1))
                self.assertFalse(second_waitpid.wait(.02))
                publish.set()
                for thread in threads:
                    thread.join(1)
        finally:
            publish.set()
            for thread in threads:
                if thread.ident is not None:
                    thread.join(1)
        self.assertFalse(errors)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(calls, [(child.pid, os.WNOHANG)])
        self.assertEqual(values, [0, 0])
        self.assertEqual(child.returncode, 0)

    def test_distinct_child_poll_is_not_globally_serialized(self):
        first, second = self.popen_fixture(900001), self.popen_fixture(900002)
        self.assertIsNot(first._state_lock, second._state_lock)
        held, release, completed = [threading.Event() for _ in range(3)]
        errors = []

        def hold():
            with first._state_lock:
                held.set()
                release.wait(1)

        def poll_other():
            try:
                second.poll()
                completed.set()
            except BaseException as error:
                errors.append(type(error).__name__)

        a, b = threading.Thread(target=hold), threading.Thread(target=poll_other)
        with patch('os.waitpid', lambda pid, flags: (pid, 0)):
            try:
                a.start()
                self.assertTrue(held.wait(1))
                b.start()
                self.assertTrue(completed.wait(.2))
            finally:
                release.set()
                a.join(1)
                if b.ident is not None:
                    b.join(1)
        self.assertFalse(errors)

    def test_even_blocking_poll_request_uses_nonblocking_waitpid(self):
        child = self.popen_fixture(900003)
        flags = []
        with patch('os.waitpid', lambda pid, flag: (flags.append(flag) or (0, 0))):
            self.assertIsNone(child.poll(0))
        self.assertEqual(flags, [os.WNOHANG])

    def test_reaped_pid_is_never_signaled(self):
        child = self.popen_fixture(900004)
        with patch('os.waitpid', return_value=(child.pid, 0)), patch('os.kill') as kill:
            self.assertEqual(child.poll(), 0)
            child._send_signal(signal.SIGKILL)
            kill.assert_not_called()

    def test_join_retries_nonwaitable_exit_without_losing_budget(self):
        child = self.popen_fixture(900005)
        clock = [0.]
        def pause(seconds): clock[0] += seconds
        with patch.object(child, 'poll', side_effect=[None, None, 0]) as poll, patch('time.monotonic', lambda: clock[0]), patch('time.sleep', pause):
            self.assertEqual(child.wait(.1), 0)
            self.assertEqual(poll.call_count, 3)
        self.assertLess(clock[0], .1)

    def test_join_of_live_child_remains_bounded(self):
        child = self.popen_fixture(900006)
        clock = [0.]
        def pause(seconds): clock[0] += seconds
        with patch.object(child, 'poll', return_value=None), patch('time.monotonic', lambda: clock[0]), patch('time.sleep', pause):
            self.assertIsNone(child.wait(.1))
        self.assertAlmostEqual(clock[0], .1)

    def test_real_children_execute_concurrently_under_stage_limit(self):
        supervisor = WorkerSupervisor()
        barrier = supervisor.context.Barrier(2)
        entered = supervisor.context.Value('i', 0)
        values, errors = [], []
        start = time.monotonic()

        def run():
            try:
                values.append(supervisor.run(ConcurrentAdapter(barrier, entered), 'observe', (), start + 1))
            except BaseException as error:
                errors.append((type(error).__name__, str(error)))

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertFalse(errors)
        self.assertEqual(values, [True, True])
        self.assertEqual(entered.value, 2)
        self.assertFalse(supervisor.active)
        self.assertFalse(supervisor.failed)
        self.assertLess(time.monotonic() - start, 1)

    def test_global_cleanup_and_owner_share_real_child_state(self):
        context = OwnedSpawnContext()
        errors, stop = [], threading.Event()

        def sweeper():
            try:
                while not stop.is_set():
                    multiprocessing.process._cleanup()
                    stop.wait(.0005)
            except BaseException as error:
                errors.append(type(error).__name__)

        thread = threading.Thread(target=sweeper)
        thread.start()
        try:
            for _ in range(12):
                process = context.Process(target=quiet_child)
                process.start()
                try:
                    process.join(.4)
                    self.assertFalse(process.is_alive())
                    self.assertEqual(process.exitcode, 0)
                finally:
                    if process.is_alive():
                        process.kill()
                    process.join(.1)
                    process.close()
        finally:
            stop.set()
            thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)

    def simulated_cleanup(self, *, unkillable=False, close_failure=False):
        supervisor = WorkerSupervisor()
        receiver, sender = supervisor.context.Pipe(duplex=False)
        sender.send_bytes(pickle.dumps(('ok', True)))
        observed = []

        class Process:
            pid = 9876
            alive = True
            def start(self): pass
            def is_alive(self): return self.alive
            def terminate(self):
                if not unkillable: self.alive = False
            def kill(self):
                if not unkillable: self.alive = False
            def join(self, timeout):
                observed.append(('join', timeout))
            def close(self):
                observed.append(('close_active', self.pid in supervisor.active))
                if close_failure: raise OSError('CLOSE_FAILED')

        process = Process()
        with patch.object(supervisor.context, 'Pipe', return_value=(receiver, sender)), patch.object(supervisor.context, 'Process', return_value=process):
            try:
                result = supervisor.run(TrueAdapter(), 'observe', (), time.monotonic() + 1)
            except BaseException as error:
                result = type(error).__name__
        return supervisor, process, observed, result, receiver, sender

    def test_unkillable_child_retains_capacity_and_poisoned_admission(self):
        supervisor, process, observed, result, receiver, sender = self.simulated_cleanup(unkillable=True)
        self.assertEqual(result, 'RuntimeError')
        self.assertTrue(supervisor.failed)
        self.assertEqual(supervisor.active, {process.pid})
        self.assertEqual(observed, [('join', .1), ('join', .1)])
        self.assertTrue(receiver.closed and sender.closed)
        with self.assertRaises(Unavailable):
            supervisor.run(TrueAdapter(), 'observe', (), time.monotonic() + 1)

    def test_close_failure_retains_capacity_and_poisoned_admission(self):
        supervisor, process, observed, result, receiver, sender = self.simulated_cleanup(close_failure=True)
        self.assertEqual(result, 'OSError')
        self.assertTrue(supervisor.failed)
        self.assertEqual(supervisor.active, {process.pid})
        self.assertIn(('close_active', True), observed)
        self.assertTrue(receiver.closed and sender.closed)

    def test_capacity_is_released_only_after_close(self):
        supervisor, process, observed, result, receiver, sender = self.simulated_cleanup()
        self.assertIs(result, True)
        self.assertIn(('close_active', True), observed)
        self.assertFalse(supervisor.active)
        self.assertFalse(supervisor.failed)
        self.assertTrue(receiver.closed and sender.closed)

    def test_timeout_kills_worker_before_late_side_effect(self):
        supervisor = WorkerSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'side-effect'
            with self.assertRaises(ExpiredDeadline):
                supervisor.run(SlowSideEffect(str(target)), 'observe', (), time.monotonic() + .04)
            self.assertFalse(supervisor.active)
            self.assertFalse(supervisor.failed)
            time.sleep(.25)
            self.assertFalse(target.exists())

    def test_unsupported_runtime_fails_before_spawn(self):
        with patch('sys.platform', 'unsupported'):
            with self.assertRaisesRegex(RuntimeError, 'UNSUPPORTED_WORKER_LIFECYCLE_RUNTIME'):
                WorkerSupervisor()

    def test_historical_worker_is_not_current_worker(self):
        root = Path(__file__).resolve().parents[1]
        original = subprocess.check_output(['git', 'show', '12e2df4c32ef51d08c799ec63a565c90221e8bcd:b23r6a/workers.py'], cwd=root)
        self.assertNotIn(b'OwnedSpawnContext', original)
        self.assertIn(b'OwnedSpawnContext', (root / 'b23r6a/workers.py').read_bytes())
        self.assertIn(b'process.join(.1)', original)


def main():
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LifecycleSecurity)
    expected = json.loads((root / 'workerclosure/test-manifest.json').read_text())
    actual = sorted(t.id().replace('__main__.', '') for t in suite)
    if actual != expected or len(actual) != len(set(actual)):
        raise RuntimeError('EXACT_LIFECYCLE_MANIFEST_MISMATCH')
    rows = []

    class Ledger(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            rows.append({'test': test.id().replace('__main__.', ''), 'status': 'STARTED'})
        def addSuccess(self, test):
            rows[-1]['status'] = 'PASS'; super().addSuccess(test)
        def addFailure(self, test, error):
            rows[-1]['status'] = 'FAIL'; super().addFailure(test, error)
        def addError(self, test, error):
            rows[-1]['status'] = 'ERROR'; super().addError(test, error)
        def addSkip(self, test, reason):
            rows[-1]['status'] = 'SKIPPED'; super().addSkip(test, reason)

    result = unittest.TextTestRunner(verbosity=2, resultclass=Ledger).run(suite)
    passed = result.wasSuccessful() and len(rows) == len(expected) and all(r['status'] == 'PASS' for r in rows)
    out = root / 'evidence'; out.mkdir(exist_ok=True)
    (out / 'workerclosure-ledger.json').write_text(json.dumps({'status': 'PASS' if passed else 'FAIL', 'expected': expected, 'executed': rows, 'skipped': len(result.skipped)}, indent=2) + '\n')
    print('WORKER_CLOSURE_EXACT', 'PASS' if passed else 'FAIL', sum(r['status'] == 'PASS' for r in rows), '/', len(expected))
    if not passed: raise SystemExit(1)


if __name__ == '__main__':
    main()
