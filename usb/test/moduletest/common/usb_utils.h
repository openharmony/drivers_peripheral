/*
 * UsbUtils.h
 *
 * usb sdk test utils source file
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef USB_UTILS_H
#define USB_UTILS_H

#include <string>

struct ProcInfo {
    double ramPeak;
    double ramAvg;
    double cpuPeak;
    double cpuAvg;
    int threadPeak;
};

extern bool HasLog(const std::string &target, double startTs, const std::string &file = "/data/acm_write_xts");
extern double GetNowTs(void);
extern char *ParseSysCmdResult(FILE &result, int line, int word);
extern void CalcProcInfoFromFile(struct ProcInfo &info, const std::string &file);
extern double GetTsFromLog(const std::string &target, double startTs, const std::string &file);

#endif