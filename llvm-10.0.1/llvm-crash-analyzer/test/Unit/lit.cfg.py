# Copyright 2022 Cisco Systems, Inc. and its affiliates
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
# SPDX-License-Identifier: Apache-2.0

# -*- Python -*-
# Configuration file for the 'lit' test runner.
import os
import subprocess
import lit.formats
# name: The name of this test suite.
config.name = 'CRASH-ANALYZER-Unit'
# suffixes: A list of file extensions to treat as test files.
config.suffixes = []
# is_early; Request to run this suite early.
config.is_early = True
# test_source_root: The root path where tests are located.
# test_exec_root: The root path where tests should be run.
config.test_exec_root = os.path.join(config.crash_analyzer_obj_root, 'unittests')
config.test_source_root = config.test_exec_root
# testFormat: The test format to use to interpret tests.
config.test_format = lit.formats.GoogleTest(config.llvm_build_mode, 'Tests')
# Propagate the temp directory. Windows requires this because it uses \Windows\
# if none of these are present.
if 'TMP' in os.environ:
    config.environment['TMP'] = os.environ['TMP']
if 'TEMP' in os.environ:
    config.environment['TEMP'] = os.environ['TEMP']
# Propagate HOME as it can be used to override incorrect homedir in passwd
# that causes the tests to fail.
if 'HOME' in os.environ:
    config.environment['HOME'] = os.environ['HOME']
