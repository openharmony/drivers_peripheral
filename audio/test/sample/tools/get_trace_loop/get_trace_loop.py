#
# Copyright (c) 2024 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys
import subprocess
import sqlite3
import threading
import time
import re
import shutil
import uuid
import random
import json
import sqlite3
import datetime
import pandas as pd
import inspect

# The following programs are packaged as exe commands
# pyinstaller --onefile get_trace_loop.py

trace_duration = 30

now_time = "null"
now_version = "null"
need_reboot = False
target_p_name = "sensor_host"
trace_file_name = ""
p_name_id = ""


# Run a cmd command
def run_cmd(cmd):
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: {cmd}")
    output = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            check=True).stdout
    print(f"{__func__}: result:{str(output)}")
    return output


# Wait for the HDC to connect to the device
def wait_for_device():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    run_cmd("hdc wait-for-device")


# Restart your device
def reboot():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    run_cmd("hdc shell reboot")


# Gets the current time, which is used as the file name part of the scraped data
def update_now_time():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    global now_time
    now_time = str(datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))


# Obtain the current device version number, which is used as the file name part of the scraped data
def update_now_version():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    global now_version
    now_version = str(run_cmd("hdc shell param get const.product.software.version")).replace("\n", "").replace(" ", "")


# Obtain the strings of process name and process ID
def get_p_name_id():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    global p_name_id
    cmd = "hdc shell \"pidof " + target_p_name + "\""
    pid = str(run_cmd(cmd)).replace("\n", "")
    p_name_id = target_p_name + "-" + pid


# Obtain the main method of trace
def get_trace():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    global trace_file_name
    trace_file_name = "trace-" + now_version + "-" + p_name_id + "-" + now_time + ".trace"
    cmd = "hdc shell \"hitrace -b 40960 -t " + str(trace_duration) + " --overwrite hdf -o /data/log/this.trace\""
    result = run_cmd(cmd)
    if "OpenRecording failed" in result:
        reboot()
        return
    cmd = "hdc file recv /data/log/this.trace " + trace_file_name
    result = run_cmd(cmd)


# Perform a one-time crawl of memory data for all processes configured
def get_data_once():
    update_now_time()
    update_now_version()
    get_p_name_id()
    get_trace()


# Perform num fetch of the memory data of all processes configured at daily intervals
def get_data_more(num, daily):
    for i in range(num):
        get_data_once()
        time.sleep(daily)


if __name__ == "__main__":
    get_data_more(10000, 0)
    pass
