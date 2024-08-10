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
import inspect

# from git import Repo

# Enter your username and password
username = '********'
password = '********'
# Enter your prs
prs = [
    "https://gitee.com/openharmony/drivers_interface/pulls/1152",
    "https://gitee.com/openharmony/drivers_peripheral/pulls/6193",
    "https://gitee.com/openharmony/multimedia_camera_framework/pulls/1750",
    "https://gitee.com/openharmony/graphic_graphic_2d/pulls/13515",
    "https://gitee.com/openharmony/multimedia_image_framework/pulls/2281",
    "https://gitee.com/openharmony/xts_hats/pulls/1212",
    "https://gitee.com/openharmony/powermgr_battery_manager/pulls/579",
    "https://gitee.com/openharmony/distributedhardware_distributed_camera/pulls/630",
]
if os.name == 'nt':
    mix = "\\"
else:
    mix = "/"
print(f'mix={mix}')
code_root = "code"
repo_name_for_code_map = {
    "drivers_peripheral": f'{code_root}{mix}drivers{mix}peripheral',
    "drivers_interface": f'{code_root}{mix}drivers{mix}interface',
    "multimedia_camera_framework": f'{code_root}{mix}foundation{mix}multimedia{mix}camera_framework',
    "graphic_graphic_2d": f'{code_root}{mix}foundation{mix}graphic{mix}graphic_2d',
    "multimedia_image_framework": f'{code_root}{mix}foundation{mix}multimedia{mix}image_framework',
    "xts_hats": f'{code_root}{mix}test{mix}xts{mix}hats',
    "powermgr_battery_manager": f'{code_root}{mix}base{mix}powermgr{mix}battery_manager',
    "distributedhardware_distributed_camera": f'{code_root}{mix}foundation{mix}distributedhardware{mix}distributed_camera',
}


# Run a cmd command, When using it, change the parameter to shell=True
# Please see this note
# Please see this note
# Please see this note
def run_cmd(cmd, path_to_work_in='.'):
    __func__ = inspect.currentframe().f_code.co_name
    print(f"{__func__}: {cmd}")
    output = ""
    try:
        output = subprocess.run(cmd, cwd=path_to_work_in, shell=False, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True,
                                check=True).stdout
    except Exception as e:
        print(f"run_cmd失败")
    print(f"{__func__}: result:{str(output)}")
    return output


# Initialize the environment conditions for accessing git
def init_environment():
    init_cmds = [
        f"export https_proxy=http://{username}:{password}@proxyhk.huawei.com:8080",
        f"export http_proxy=http://{username}:{password}@proxyhk.huawei.com:8080",
        f"export https_proxy=http://{username}:{password}@proxy.huawei.com:8080",
        f"export http_proxy=http://{username}:{password}@proxy.huawei.com:8080",
        f"git config --global https.proxy http://{username}:{password}@proxyhk.huawei.com:8080",
        f"git config --global http.proxy http://{username}:{password}@proxyhk.huawei.com:8080",
        f"git config --global https.proxy http://{username}:{password}@proxy.huawei.com:8080",
        f"git config --global http.proxy http://{username}:{password}@proxy.huawei.com:8080",
        f"git config --global http.sslVerify false"
    ]
    for cmd in init_cmds:
        run_cmd(cmd)


# Get the repository name and PR number
def extract_repo_and_pr(url):
    # 分割 URL 以获取路径部分
    path = url.split('/')[-3:]
    # 假设 URL 格式总是符合 gitee.com/<用户名>/<仓库名>/pulls/<PR号>
    # path[-3] 是用户名，path[-2] 是 'pulls'，path[-1] 是 PR 号
    # 但我们只对仓库名和 PR 号感兴趣
    repo_name = path[-3]  # 修正为直接取仓库名
    pr_number = path[-1]
    return repo_name, pr_number


# Read the file diff from the files.json of the PR
def read_diff_files(repo_name):
    diff_files = []
    path = f'{repo_name}{mix}files.json'
    if os.path.exists(path):
        files = open(f'{repo_name}{mix}files.json', 'r', encoding='utf-8')
        json_obj = json.loads(files.read())
        for o in json_obj['diffs']:
            diff_files.append(o['head']['name'])
    else:
        print(f'不存在文件：{path}')
    return diff_files


# Change the slash in the path to a system match
def change_mix(txt):
    if "\\" in txt:
        return str(txt).replace("\\", mix)
    if "/" in txt:
        return str(txt).replace("/", mix)


# Push the diff file to the project code
def push_diff_file_to_code(repo_name, target_path, diff_files):
    for diff_file in diff_files:
        old_file_path = f'{repo_name}{mix}{diff_file}'
        new_file_path = f'{target_path}{mix}{diff_file}'
        if os.path.exists(old_file_path):
            os.makedirs(os.path.dirname(new_file_path), exist_ok=True)
            shutil.copy(old_file_path, new_file_path)
        else:
            print(f'不存在文件：{old_file_path}')


# Submit a single repository
def git_commit(repo_name, pr_number, target_path):
    try:
        run_cmd(f'repo start ohos_{repo_name}_pr_{pr_number}', target_path)
        run_cmd(f'git add .', target_path)
        commit_msg = ("TicketNo: DTS2024012002271\nDescription:test\nTeam:OTHERS\nFeature or Bugfix:Bugfix\n"
                      "Binary Source:No\nPrivateCode(Yes/No):No")
        run_cmd(f'git commit -m "' + commit_msg + '"', target_path)
    except Exception as e:
        print(f"git_commit{repo_name}仓库失败")


# Upload as a CR link
def repo_upload(target_path):
    print("please goto code and run \"repo upload\"")
    # run_cmd(f'repo upload .', target_path)


# Download the codes and diffs for all PRs
def download_prs(pr):
    repo_name, pr_number = extract_repo_and_pr(pr)
    clone_git_url = f"https://gitee.com/openharmony/{repo_name}.git"
    cmd = f"git clone {clone_git_url}"
    try:
        if not os.path.exists(repo_name):
            run_cmd(cmd)
        else:
            print(f"已存在{repo_name}")
        cmd = f'git fetch {clone_git_url} pull/{pr_number}/head:pr_{pr_number}'
        run_cmd(cmd, repo_name)
        run_cmd(f'git checkout pr_{pr_number}', repo_name)
    except Exception as e:
        print(f"获取{repo_name}仓库的pull_{pr_number}失败")
    files_url = f'{pr}/files.json'
    files_target_path = f'{repo_name}{mix}files.json'
    if not os.path.exists(files_target_path):
        cmd = f'curl -o {files_target_path} {files_url} --ssl-no-revoke'
        try:
            run_cmd(cmd)
        except Exception as e:
            print(f"获取{repo_name}仓库的files失败")
    else:
        print(f"已存在{files_target_path}")
    diff_files = read_diff_files(repo_name)

    if repo_name not in repo_name_for_code_map:
        print(f"{repo_name}配置路径不存在，请配置")
        return
    target_path = repo_name_for_code_map[repo_name]

    push_diff_file_to_code(repo_name, target_path, diff_files)
    git_commit(repo_name, pr_number, target_path)
    repo_upload(target_path)


if __name__ == "__main__":
    init_environment()
    for pr in prs:
        download_prs(pr)
    pass
