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

"""Checks that sign_target_files_apks.main() records the YRRP profile steps."""

import importlib
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

# Outside a full Android tree these modules are missing. Stub only the ones
# that fail to load, so the real modules are used inside the tree.
for _name in ("avbtool", "google", "google.protobuf",
              "google.protobuf.descriptor", "google.protobuf.descriptor_pool",
              "google.protobuf.symbol_database", "google.protobuf.internal",
              "google.protobuf.internal.builder",
              "google.protobuf.runtime_version", "ota_metadata_pb2",
              "apex_manifest", "update_payload"):
  try:
    importlib.import_module(_name)
  except Exception:  # pylint: disable=broad-except
    sys.modules[_name] = mock.MagicMock()

# pylint: disable=wrong-import-position
import sign_target_files_apks as signer
import yrrp_signing_profile as profiler

HEAVY_CALLS = (
    "common.LoadInfoDict", "BuildKeyMap", "common.ReadApkCerts",
    "GetApkCerts", "ReadApexKeysInfo", "GetApexKeys",
    "CheckApkAndApexKeysAvailable", "common.GetKeyPasswords",
    "GetApiLevelAndCodename", "GetCodenameToApiLevelMap",
    "ProcessTargetFiles", "add_img_to_target_files.main",
)

EXPECTED_STEPS = [
    "load-keys", "process-target-files", "zip-close",
    "add-img-to-target-files",
]


class SigningHooksTest(unittest.TestCase):

  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.source = os.path.join(self.temp.name, "in.zip")
    zipfile.ZipFile(self.source, "w").close()
    self.output = os.path.join(self.temp.name, "out.zip")
    self.dir = os.path.join(self.temp.name, "profile")
    for name in HEAVY_CALLS:
      owner, _, attr = name.rpartition(".")
      target = getattr(signer, owner) if owner else signer
      patcher = mock.patch.object(target, attr)
      patcher.start()
      self.addCleanup(patcher.stop)
    signer.common.ReadApkCerts.return_value = ({}, None)
    signer.common.GetKeyPasswords.return_value = {}
    signer.GetApiLevelAndCodename.return_value = (36, None)

  def run_main(self):
    with mock.patch.dict(os.environ, {profiler.ENV_VAR: self.dir}):
      try:
        signer.main([self.source, self.output])
      finally:
        profiler.finish_active()

  def steps(self):
    with open(os.path.join(self.dir, "timeline.jsonl")) as handle:
      return [json.loads(line) for line in handle]

  def test_main_records_the_four_steps_in_order(self):
    self.run_main()
    steps = self.steps()
    self.assertEqual([s["step"] for s in steps], EXPECTED_STEPS)
    self.assertTrue(all(s["ok"] for s in steps))

  def test_failure_inside_a_step_marks_it_not_ok(self):
    signer.ProcessTargetFiles.side_effect = RuntimeError("signing failed")
    with self.assertRaises(RuntimeError):
      self.run_main()
    self.assertEqual(
        [(s["step"], s["ok"]) for s in self.steps()],
        [("load-keys", True), ("process-target-files", False)])


if __name__ == "__main__":
  unittest.main()
