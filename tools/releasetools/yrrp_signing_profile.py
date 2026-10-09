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

"""Opt-in resource profile for sign_target_files_apks.

Set YRRP_SIGNING_PROFILE_DIR to a directory to record a step timeline there.
When the variable is unset, every call is a no-op and signing behaves exactly
as upstream.
"""

ENV_VAR = "YRRP_SIGNING_PROFILE_DIR"
SAMPLE_INTERVAL_S = 1.0


class NoopProfile(object):
  """Stands in for a profile when profiling is off or broken."""

  def mark(self, name):
    pass

  def finish(self, ok=True):
    pass


def start(environ=None, interval_s=SAMPLE_INTERVAL_S):
  """Returns the profile for this signing run."""
  return NoopProfile()
