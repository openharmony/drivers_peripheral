#!/bin/bash
# usb_watch_process.sh
#
# usb sdk test shell script file
#
# Copyright (c) 2020-2021 Huawei Device Co., Ltd.
#
# This software is licensed under the terms of the GNU General Public
# License version 2, as published by the Free Software Foundation, and
# may be copied, distributed, and modified under those terms.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

set -e

pid=$(pidof $1)
interval=1
log_file="/data/usb_proclog.txt"
cat /dev/null > $log_file
while true
do
cat /proc/${pid}/status | grep -e VmRSS >> $log_file
cpu=$(top -n 1 -p ${pid} | head -6 | tail -1 | cut -F 10)
echo "Cpu:" $cpu >> $log_file
cat /proc/${pid}/status | grep -e Threads >> $log_file
sleep $interval
done