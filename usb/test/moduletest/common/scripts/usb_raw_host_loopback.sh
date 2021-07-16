#!/bin/bash
# usb_raw_host_loopback.sh
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

device="/dev/ttyACM0"
stty -F "$device" raw speed 115200 min 0 time 5
port=$(lsusb -t| grep cdc_acm | tail -1 | awk -F'[ :]+' '{print $4}')
usb_dir="/sys/bus/usb/devices/1-${port}"

while true
do
    if [ ! -e $device ];then
        echo "$device not exists"
        sleep 1
        continue
    fi
    data=$(cat $device)
    if [ "$data" == "GET_DESCRIPTOR" ];then
        id_vendor=$(cat ${usb_dir}/idVendor)
        id_product=$(cat ${usb_dir}/idProduct)
        bcd_device=$(cat ${usb_dir}/bcdDevice)
        b_configuration_value=$(cat ${usb_dir}/bConfigurationValue)
        echo "$id_vendor" "$id_product" "$bcd_device" "$b_configuration_value"
        echo -n "$id_vendor" "$id_product" "$bcd_device" "$b_configuration_value"> $device
    fi
    if [ ! "${data}x" == "x" ];then
        echo "$data"
        echo -n "$data" > $device
    fi
done