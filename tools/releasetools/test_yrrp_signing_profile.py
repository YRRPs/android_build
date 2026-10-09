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

import json
import os
import subprocess
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
  unittest.main()
