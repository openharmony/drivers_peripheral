#!/bin/bash
# usb_device_loopback.sh
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

IFS=$'\n'
read_log_file="/data/acm_read_xts"
usb_dir="/sys/bus/usb/devices/1-1"
max_ts=0
pid=$(ps -ef | grep 'usbhost_ddk_test' | grep -v grep | cut -F 2)
if [ ! "${pid}x" == "x" ];then
    killall usbhost_ddk_test
fi
usbhost_ddk_test -Ar &
cat /dev/null > $read_log_file
while true
do
    lines=$(cat $read_log_file)
    cat /dev/null > $read_log_file
    for line in $lines
    do
        ts=$(echo $line | grep 'XTSCHECK' | cut -F 2 | cut -d ',' -f 1)
        if [ `echo "$ts > $max_ts" | bc` -eq 1 ];then
            max_ts=$ts
            data=$(echo $line | grep 'XTSCHECK' | cut -F 4 | cut -d '[|]' -f 2 )
            echo "[`date +%s.%N`]" $data
            usbhost_ddk_test -Aw $data
        fi
        if [ "$data" == "GET_DESCRIPTOR" ];then
            id_vendor=$(cat ${usb_dir}/idVendor)
            id_product=$(cat ${usb_dir}/idProduct)
            bcd_device=$(cat ${usb_dir}/bcdDevice)
            b_configuration_value=$(cat ${usb_dir}/bConfigurationValue)
            echo "[`date +%s.%N`]" "$id_vendor $id_product $bcd_device $b_configuration_value"
            usbhost_ddk_test -Aw "$id_vendor $id_product $bcd_device $b_configuration_value"
        fi
    done
    sleep 0.1
done