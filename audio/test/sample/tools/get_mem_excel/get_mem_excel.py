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
# pyinstaller --onefile get_mem_excel.py

now_time = "null"
now_version = "null"
hidumper_num = 0
pid_list = []
mem_file_name = ""
mem_smaps_file_name = ""


# Run a cmd command
def run_cmd(cmd):
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: {cmd}")
    output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            check=True).stdout
    print(f"{__func__}: result:{str(output)}")
    return output


# Wait for the HDC to connect to the device
def wait_for_device():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    run_cmd("hdc wait-for-device")


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


# Obtain the list of process names to be captured from the pid_list.txt, if not configured, there is a default value
def get_pid_list():
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    global pid_list
    list_file_path = "pid_list.txt"
    if os.path.exists(list_file_path):
        list_file = open(list_file_path, 'r')
        for line in list_file.readlines():
            pid_list.append(line.replace('\n', ''))
    else:
        print(f"{__func__}: pid_list.txt not exists, get mem for sensor_host,vibrator_host,audio_host,allocator_host")
        pid_list.append('sensor_host')
        pid_list.append('vibrator_host')
        pid_list.append('audio_host')
        pid_list.append('allocator_host')


# Grab simple memory information for a process
def get_mem(p_name):
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in, p_name {p_name}")
    global mem_file_name
    mem_file_name = "result-mem" + now_version + p_name + now_time + ".txt"
    cmd = "hdc shell \"hidumper --mem `pidof " + p_name + "`\" > " + mem_file_name
    run_cmd(cmd)


# Fetch detailed memory information for a process
def get_mem_smaps(p_name):
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in, p_name {p_name}")
    global mem_smaps_file_name
    mem_smaps_file_name = "result-mem_smaps" + now_version + p_name + now_time + ".txt"
    cmd = "hdc shell \"hidumper --mem-smaps `pidof " + p_name + "` -v\" > " + mem_smaps_file_name
    run_cmd(cmd)


# Parse Excel sheets based on detailed memory information for a process
def get_mem_smaps_excel(p_name):
    global hidumper_num
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: in")
    mem_file = open(mem_smaps_file_name, "r")
    datas = mem_file.readlines()
    result_map = {}
    result_list = []
    mem_index = -1
    for line in datas:
        fields = line.split()
        if len(fields) > 2 and 'Pss' in fields:
            hidumper_num = len(fields)
            mem_index = fields.index("Pss")
            continue
        if len(fields) == 10:
            mem_data = int(fields[mem_index])
            result_map["总和"] = mem_data
            continue
        if len(fields) != hidumper_num or hidumper_num == 0 or mem_index == -1:
            continue
        mem_data = int(fields[mem_index])
        mem_name = fields[hidumper_num - 1]
        matchs = [
            r'\[anon:guard:\d*\]',
            r'\[anon:stack:\d*\]',
            r'\[anon:signal_stack:\d*\]'
        ]
        for match in matchs:
            if re.findall(match, mem_name):
                mem_name = match
        if mem_name not in result_map:
            result_map[mem_name] = 0
        result_map[mem_name] += mem_data
    for key in result_map:
        result_list.append([key, result_map[key]])
    headers = ['作用域名', '内存值']
    df = pd.DataFrame(result_list, columns=headers)
    output_file = "result-mem-" + now_version + p_name + now_time + ".xlsx"
    df.to_excel(output_file, index=False)


# Scrape a process's in-memory data
def get_data(p_name):
    get_mem(p_name)
    get_mem_smaps(p_name)
    get_mem_smaps_excel(p_name)


# Scrapes the memory data of all configured processes
def get_all_process_data():
    for p_name in pid_list:
        get_data(p_name)


# Perform a one-time crawl of memory data for all processes configured
def get_data_once():
    wait_for_device()
    update_now_time()
    update_now_version()
    get_all_process_data()


# Perform num fetch of the memory data of all processes configured at daily intervals
def get_data_more(num, daily):
    for i in range(num):
        get_data_once()
        time.sleep(daily)


if __name__ == "__main__":
    get_pid_list()
    get_data_more(1, 10)
    pass
