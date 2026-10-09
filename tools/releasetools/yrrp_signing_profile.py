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

import json
import os
import resource
import time

ENV_VAR = "YRRP_SIGNING_PROFILE_DIR"
SAMPLE_INTERVAL_S = 1.0


class NoopProfile(object):
  """Stands in for a profile when profiling is off or broken."""

  def mark(self, name):
    pass

  def finish(self, ok=True):
    pass


def _io_counters():
  """Returns read and write bytes of this process, or None without /proc."""
  try:
    with open("/proc/self/io") as handle:
      fields = dict(line.split(":", 1) for line in handle if ":" in line)
    return int(fields["read_bytes"]), int(fields["write_bytes"])
  except (OSError, KeyError, ValueError):
    return None


def _snapshot():
  return {
      "wall": time.monotonic(),
      "self": resource.getrusage(resource.RUSAGE_SELF),
      "children": resource.getrusage(resource.RUSAGE_CHILDREN),
      "io": _io_counters(),
  }


def _cpu(usage):
  return usage.ru_utime + usage.ru_stime


def _delta(before, after):
  """Resource use between two snapshots.

  Page faults include reaped children. Read and write bytes and context
  switches cover this process only. maxrss values are process peaks in KiB,
  not deltas.
  """
  self_b, self_a = before["self"], after["self"]
  kids_b, kids_a = before["children"], after["children"]
  io_ok = before["io"] is not None and after["io"] is not None
  return {
      "wall_s": round(after["wall"] - before["wall"], 3),
      "cpu_self_s": round(_cpu(self_a) - _cpu(self_b), 3),
      "cpu_children_s": round(_cpu(kids_a) - _cpu(kids_b), 3),
      "maxrss_self_kb": self_a.ru_maxrss,
      "maxrss_children_kb": kids_a.ru_maxrss,
      "minflt": (self_a.ru_minflt - self_b.ru_minflt
                 + kids_a.ru_minflt - kids_b.ru_minflt),
      "majflt": (self_a.ru_majflt - self_b.ru_majflt
                 + kids_a.ru_majflt - kids_b.ru_majflt),
      "read_bytes": after["io"][0] - before["io"][0] if io_ok else None,
      "write_bytes": after["io"][1] - before["io"][1] if io_ok else None,
      "nvcsw": self_a.ru_nvcsw - self_b.ru_nvcsw,
      "nivcsw": self_a.ru_nivcsw - self_b.ru_nivcsw,
  }


class Profile(object):
  """Writes a step timeline into a directory."""

  def __init__(self, directory, interval_s):
    os.makedirs(directory, exist_ok=True)
    self.directory = directory
    self._timeline = open(self._path("timeline.jsonl"), "a")
    self._steps = []
    self._open_step = None
    self._finished = False

  def _path(self, name):
    return os.path.join(self.directory, name)

  def mark(self, name):
    """Ends the running step as ok and starts the step called name."""
    self._close_step(ok=True)
    self._open_step = (name, _snapshot())

  def finish(self, ok=True):
    """Ends the running step with ok. Later calls do nothing."""
    if self._finished:
      return
    self._finished = True
    self._close_step(ok=ok)
    self._timeline.close()

  def _close_step(self, ok):
    if self._open_step is None:
      return
    name, before = self._open_step
    self._open_step = None
    record = {"step": name, "ok": ok}
    record.update(_delta(before, _snapshot()))
    self._steps.append(record)
    self._timeline.write(json.dumps(record) + "\n")
    self._timeline.flush()


def start(environ=None, interval_s=SAMPLE_INTERVAL_S):
  """Returns the profile for this signing run."""
  environ = os.environ if environ is None else environ
  directory = environ.get(ENV_VAR)
  if not directory:
    return NoopProfile()
  return Profile(directory, interval_s)
