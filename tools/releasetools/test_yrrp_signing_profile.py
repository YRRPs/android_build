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

import os
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


if __name__ == "__main__":
  unittest.main()
