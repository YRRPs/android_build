#
# Copyright (C) 2026 The YRRPs Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Unit tests for yrrp_signing_profile."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yrrp_signing_profile as profiler


class NoopProfileTest(unittest.TestCase):

  def test_unset_variable_gives_noop_that_writes_nothing(self):
    with tempfile.TemporaryDirectory() as root:
      cwd = os.getcwd()
      os.chdir(root)
      try:
        profile = profiler.start(environ={}, interval_s=0.01)
        profile.mark("a")
        profile.finish(ok=True)
      finally:
        os.chdir(cwd)
      self.assertIsInstance(profile, profiler.NoopProfile)
      self.assertEqual(os.listdir(root), [])


STEP_FIELDS = {
    "step", "ok", "wall_s", "cpu_self_s", "cpu_children_s",
    "maxrss_self_kb", "maxrss_children_kb", "minflt", "majflt",
    "read_bytes", "write_bytes", "nvcsw", "nivcsw",
}


def read_jsonl(path):
  with open(path) as handle:
    return [json.loads(line) for line in handle]


class TimelineTest(unittest.TestCase):

  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.dir = os.path.join(self.temp.name, "profile")
    self.profile = profiler.start(
        environ={profiler.ENV_VAR: self.dir}, interval_s=0.01)

  def tearDown(self):
    self.profile.finish(ok=True)
    self.temp.cleanup()

  def timeline(self):
    return read_jsonl(os.path.join(self.dir, "timeline.jsonl"))

  def test_marks_record_each_step_with_every_field(self):
    self.profile.mark("first")
    self.profile.mark("second")
    self.profile.finish(ok=True)
    steps = self.timeline()
    self.assertEqual([s["step"] for s in steps], ["first", "second"])
    self.assertTrue(all(s["ok"] for s in steps))
    for step in steps:
      self.assertEqual(set(step), STEP_FIELDS)

  def test_failed_finish_marks_last_step_not_ok(self):
    self.profile.mark("only")
    self.profile.finish(ok=False)
    self.assertEqual(
        [(s["step"], s["ok"]) for s in self.timeline()], [("only", False)])

  def test_child_cpu_is_counted(self):
    self.profile.mark("busy-child")
    subprocess.run(
        [sys.executable, "-c", "sum(i * i for i in range(3000000))"],
        check=True)
    self.profile.finish(ok=True)
    self.assertGreater(self.timeline()[0]["cpu_children_s"], 0.05)


class OutputTest(unittest.TestCase):

  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.dir = os.path.join(self.temp.name, "profile")

  def tearDown(self):
    self.temp.cleanup()

  def path(self, name):
    return os.path.join(self.dir, name)

  def run_profile(self):
    profile = profiler.start(
        environ={profiler.ENV_VAR: self.dir}, interval_s=0.01)
    profile.mark("work")
    sum(i * i for i in range(200000))
    time.sleep(0.05)
    profile.finish(ok=True)
    return profile

  def test_sampler_writes_samples_and_stops(self):
    profile = self.run_profile()
    samples = read_jsonl(self.path("samples.jsonl"))
    self.assertGreaterEqual(len(samples), 2)
    self.assertEqual(
        set(samples[0]),
        {"t_s", "rss_kb", "swap_kb", "tmp_used_bytes", "minflt", "majflt"})
    self.assertGreater(samples[0]["rss_kb"], 0)
    self.assertFalse(profile._sampler.is_alive())

  def test_finish_writes_profile_top_and_summary_once(self):
    profile = self.run_profile()
    for name in ("signing.prof", "signing-top.txt", "summary.json"):
      self.assertGreater(os.path.getsize(self.path(name)), 0, name)
    with open(self.path("summary.json")) as handle:
      summary = json.load(handle)
    self.assertEqual(
        set(summary),
        {"nproc", "python", "wall_s", "steps", "peak_rss_kb",
         "peak_swap_kb", "peak_tmp_used_bytes", "tmp_dir"})
    self.assertEqual([s["step"] for s in summary["steps"]], ["work"])
    self.assertGreater(summary["peak_rss_kb"], 0)
    with open(self.path("signing-top.txt")) as handle:
      text = handle.read()
    self.assertIn("by self time", text)
    self.assertIn("by cumulative time", text)
    os.remove(self.path("summary.json"))
    profile.finish(ok=True)
    self.assertFalse(os.path.exists(self.path("summary.json")))

  def test_unwritable_directory_warns_once_and_goes_noop(self):
    blocker = os.path.join(self.temp.name, "file")
    with open(blocker, "w") as handle:
      handle.write("x")
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
      profile = profiler.start(
          environ={profiler.ENV_VAR: os.path.join(blocker, "profile")})
      profile.mark("a")
      profile.finish(ok=True)
    self.assertIsInstance(profile, profiler.NoopProfile)
    self.assertEqual(
        stderr.getvalue().count("YRRP signing profile disabled"), 1)

  def test_write_failure_mid_run_warns_once_and_signing_continues(self):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
      profile = profiler.start(
          environ={profiler.ENV_VAR: self.dir}, interval_s=0.01)
      broken = mock.MagicMock()
      broken.write.side_effect = OSError("disk full")
      profile._timeline = broken
      profile.mark("a")
      profile.mark("b")
      profile.mark("c")
      profile.finish(ok=True)
    self.assertEqual(
        stderr.getvalue().count("YRRP signing profile disabled"), 1)


class FinishActiveTest(unittest.TestCase):

  def test_finish_active_inside_failing_finally_marks_not_ok(self):
    with tempfile.TemporaryDirectory() as root:
      directory = os.path.join(root, "profile")
      with self.assertRaises(ValueError):
        try:
          profiler.start(environ={profiler.ENV_VAR: directory}).mark("boom")
          raise ValueError("signing failed")
        finally:
          profiler.finish_active()
      step = read_jsonl(os.path.join(directory, "timeline.jsonl"))[0]
      self.assertEqual((step["step"], step["ok"]), ("boom", False))

  def test_finish_active_without_start_does_nothing(self):
    profiler.finish_active()


if __name__ == "__main__":
  unittest.main()
