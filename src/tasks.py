# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery
from .providers import yeti

import yara

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-yara-scan.tasks.yara-scan"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Yara scan",
    "description": "Scans a folder with Yara rules obtained from Yeti",
    # Configuration that will be rendered as a web for in the UI, and any data entered
    # by the user will be available to the task function when executing (task_config).
    "task_config": [
        # {
        #     "name": "<REPLACE_WITH_NAME>",
        #     "label": "<REPLACE_WITH_LABEL>",
        #     "description": "<REPLACE_WITH_DESCRIPTION>",
        #     "type": "<REPLACE_WITH_TYPE>",  # Types supported: text, textarea, checkbox
        #     "required": False,
        # },
    ],
}

ALLOWED_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Run <REPLACE_WITH_COMMAND> on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    output_files = []
    provider = yeti.YetiIntelProvider()

    all_patterns = provider.get_yara_rules()
    output_file = create_output_file(output_path, display_name="all.yara")
    with open(output_file.path, "w") as fh:
        fh.write(all_patterns)

    output_files.append(output_file.to_dict())

    files_scanned = 0
    files_matched = 0
    progress = {"files_scanned": files_scanned, "matches": files_matched}
    self.send_event("task-progress", data=progress)

    for input_file in get_input_files(pipe_result, input_files):
        print(input_file)
        internal_path = input_file.get("path")
        filepath = input_file.get("display_name")
        print(f"Scanning file: ({filepath}) {internal_path}")
        # externals = ALLOWED_EXTERNALS.copy()
        externals = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "extension": input_file.get("extension"),
            "filetype": input_file.get("data_type"),
            "owner": "",
        }
        compiled_rules = yara.compile(output_file.path, externals=externals)
        matches = compiled_rules.match(internal_path)
        files_scanned += 1
        if matches:
            files_matched += 1

        for match in matches:
            print(f"Matched rule: {match.rule}")
            print(f"Matched strings: {match.strings}")
            print(f"Matched meta: {match.meta}")

        progress["files_scanned"] = files_scanned
        progress["files_matched"] = files_matched
        self.send_event("task-progress", data=progress)

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command="yeti api query",
        meta=progress,
    )
