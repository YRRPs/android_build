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

Set YRRP_SIGNING_PROFILE_DIR to a directory to record a step timeline,
resource samples every second, and a cProfile dump there. When the variable is
unset, every call is a no-op and signing behaves exactly as upstream.

Profiling never fails signing: any error inside the profiler prints one
warning to stderr and stops the profile from writing anything more.
"""

import cProfile
import io
import json
import os
import platform
import pstats
import resource
import sys
import tempfile
import threading
import time

ENV_VAR = "YRRP_SIGNING_PROFILE_DIR"
SAMPLE_INTERVAL_S = 1.0
TOP_FUNCTIONS = 40
WARNING = "YRRP signing profile disabled: %s\n"

_active = None


class NoopProfile(object):
  """Stands in for a profile when profiling is off or broken."""

  def mark(self, name):
    pass

  def finish(self, ok=True):
    pass


def _warn(error):
  sys.stderr.write(WARNING % error)


def _status_kb(*keys):
  """Reads kB fields such as VmRSS from /proc/self/status; None if absent."""
  values = dict.fromkeys(keys)
  try:
    with open("/proc/self/status") as handle:
      for line in handle:
        key, _, rest = line.partition(":")
        if key in values:
          values[key] = int(rest.split()[0])
  except (OSError, ValueError, IndexError):
    pass
  return values


def _tmp_used_bytes(path):
  """Used bytes on the filesystem holding path, including other writers."""
  try:
    stat = os.statvfs(path)
  except OSError:
    return None
  return (stat.f_blocks - stat.f_bfree) * stat.f_frsize


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
  """Writes a step timeline, resource samples, and a cProfile dump."""

  def __init__(self, directory, interval_s):
    os.makedirs(directory, exist_ok=True)
    self.directory = directory
    self._timeline = open(self._path("timeline.jsonl"), "a")
    self._samples = open(self._path("samples.jsonl"), "a")
    self._tmp_dir = tempfile.gettempdir()
    self._started = time.monotonic()
    self._steps = []
    self._open_step = None
    self._finished = False
    self._broken = False
    self._peaks = {"rss_kb": 0, "swap_kb": 0, "tmp_used_bytes": 0}
    self._stop = threading.Event()
    self._sampler = threading.Thread(
        target=self._sample_loop, args=(interval_s,),
        name="yrrp-signing-sampler", daemon=True)
    self._profiler = cProfile.Profile()
    try:
      self._profiler.enable()
    except ValueError as error:  # Another profiler already runs.
      _warn(error)
      self._profiler = None
    try:
      self._sampler.start()
    except BaseException:
      self._release()
      raise

  def _release(self):
    """Disables cProfile and closes both files, warning on any error."""
    if self._profiler is not None:
      self._profiler.disable()
    for handle in (self._timeline, self._samples):
      try:
        handle.close()
      except Exception as error:  # pylint: disable=broad-except
        self._fail(error)

  def _path(self, name):
    return os.path.join(self.directory, name)

  def mark(self, name):
    """Ends the running step as ok and starts the step called name."""
    if self._broken:
      return
    try:
      self._close_step(ok=True)
      self._open_step = (name, _snapshot())
    except Exception as error:  # pylint: disable=broad-except
      self._fail(error)

  def finish(self, ok=True):
    """Ends the running step with ok and writes the outputs once."""
    if self._finished:
      return
    self._finished = True
    try:
      if self._profiler is not None:
        self._profiler.disable()
      if not self._broken:
        self._close_step(ok=ok)
      self._stop.set()
      self._sampler.join(timeout=10)
      if not self._broken:
        self._write_outputs()
    except Exception as error:  # pylint: disable=broad-except
      self._fail(error)
    finally:
      self._release()

  def _write_outputs(self):
    if self._profiler is not None:
      self._profiler.dump_stats(self._path("signing.prof"))
      self._write_text("signing-top.txt", self._top_text())
    self._write_text("summary.json", json.dumps(self._summary(), indent=2))

  def _fail(self, error):
    if not self._broken:
      self._broken = True
      _warn(error)

  def _append(self, handle, record):
    if self._broken:
      return
    try:
      handle.write(json.dumps(record) + "\n")
      handle.flush()
    except Exception as error:  # pylint: disable=broad-except
      self._fail(error)

  def _write_text(self, name, text):
    with open(self._path(name), "w") as handle:
      handle.write(text)

  def _close_step(self, ok):
    if self._open_step is None:
      return
    name, before = self._open_step
    self._open_step = None
    record = {"step": name, "ok": ok}
    record.update(_delta(before, _snapshot()))
    self._steps.append(record)
    self._append(self._timeline, record)

  def _sample_loop(self, interval_s):
    while not self._broken:
      try:
        self._sample()
      except Exception as error:  # pylint: disable=broad-except
        self._fail(error)
      if self._stop.wait(interval_s):
        return

  def _sample(self):
    status = _status_kb("VmRSS", "VmSwap")
    usage = resource.getrusage(resource.RUSAGE_SELF)
    record = {
        "t_s": round(time.monotonic() - self._started, 3),
        "rss_kb": status["VmRSS"],
        "swap_kb": status["VmSwap"],
        "tmp_used_bytes": _tmp_used_bytes(self._tmp_dir),
        "minflt": usage.ru_minflt,
        "majflt": usage.ru_majflt,
    }
    for key in self._peaks:
      if record[key] is not None:
        self._peaks[key] = max(self._peaks[key], record[key])
    self._append(self._samples, record)

  def _top_text(self):
    out = io.StringIO()
    stats = pstats.Stats(self._profiler, stream=out)
    out.write("== by self time ==\n")
    stats.sort_stats("tottime").print_stats(TOP_FUNCTIONS)
    out.write("\n== by cumulative time ==\n")
    stats.sort_stats("cumulative").print_stats(TOP_FUNCTIONS)
    return out.getvalue()

  def _summary(self):
    return {
        "nproc": len(os.sched_getaffinity(0)),
        "python": platform.python_version(),
        "wall_s": round(time.monotonic() - self._started, 3),
        "steps": self._steps,
        "peak_rss_kb": self._peaks["rss_kb"],
        "peak_swap_kb": self._peaks["swap_kb"],
        "peak_tmp_used_bytes": self._peaks["tmp_used_bytes"],
        "tmp_dir": self._tmp_dir,
    }


def start(environ=None, interval_s=SAMPLE_INTERVAL_S):
  """Returns the profile for this signing run and makes it the active one."""
  global _active
  environ = os.environ if environ is None else environ
  directory = environ.get(ENV_VAR)
  profile = NoopProfile()
  if directory:
    try:
      profile = Profile(directory, interval_s)
    except Exception as error:  # pylint: disable=broad-except
      _warn(error)
  _active = profile
  return profile


def finish_active():
  """Finishes the profile from start(); not ok while an exception unwinds."""
  global _active
  profile, _active = _active, None
  if profile is None:
    return
  try:
    profile.finish(ok=sys.exc_info()[0] is None)
  except Exception as error:  # pylint: disable=broad-except
    _warn(error)
