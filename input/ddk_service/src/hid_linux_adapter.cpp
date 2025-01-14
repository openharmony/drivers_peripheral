/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hid_linux_adapter.h"

#include <hdf_base.h>
#include "input_uhdf_log.h"
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <linux/hiddev.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <memory.h>
#include <securec.h>

#define HDF_LOG_TAG hid_linux_adapter

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
#ifndef HIDIOCGINPUT
#define HIDIOCGINPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0A, len)
#endif
#ifndef HIDIOCSOUTPUT
#define HIDIOCSOUTPUT(len)   _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0B, len)
#endif
#ifndef HIDIOCGOUTPUT
#define HIDIOCGOUTPUT(len)   _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0C, len)
#endif
#ifndef HIDIOCSINPUT
#define HIDIOCSINPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x09, len)
#endif

int32_t LinuxHidOsAdapter::GetRawInfo(int32_t fd, HidRawDevInfo& rawDevInfo)
{
    struct hidraw_devinfo info;
    (void)memset_s(&info, sizeof(info), 0x0, sizeof(info));

    int32_t ret = ioctl(fd, HIDIOCGRAWINFO, &info);
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    rawDevInfo.busType = info.bustype;
    rawDevInfo.vendor = info.vendor;
    rawDevInfo.product = info.product;

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::GetRawName(int32_t fd, std::vector<uint8_t>& data)
{
    int32_t ret = ioctl(fd, HIDIOCGRAWNAME(data.size()), data.data());
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::GetPhysicalAddress(int32_t fd, std::vector<uint8_t>& data)
{
    int32_t ret = ioctl(fd, HIDIOCGRAWPHYS(data.size()), data.data());
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::GetRawUniqueId(int32_t fd, std::vector<uint8_t>& data)
{
    int32_t ret = ioctl(fd, HIDIOCGRAWUNIQ(data.size()), data.data());
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::SendReport(int32_t fd, HidReportType reportType, const std::vector<uint8_t>& data)
{
    unsigned long int req = 0;
    switch (reportType) {
        case HID_INPUT_REPORT:
            req = HIDIOCSINPUT(data.size());
            break;
        case HID_OUTPUT_REPORT:
            req = HIDIOCSOUTPUT(data.size());
            break;
        case HID_FEATURE_REPORT:
            req = HIDIOCSFEATURE(data.size());
            break;
        default:
            HDF_LOGE("%{public}s: invalid report type", __func__);
            return HID_DDK_INVALID_PARAMETER;
    }

    int32_t res = ioctl(fd, req, data.data());
    if (res < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::GetReport(int32_t fd, HidReportType reportType, std::vector<uint8_t>& data)
{
    unsigned long int req = 0;
    switch (reportType) {
        case HID_INPUT_REPORT:
            req = HIDIOCGINPUT(data.size());
            break;
        case HID_OUTPUT_REPORT:
            req = HIDIOCGOUTPUT(data.size());
            break;
        case HID_FEATURE_REPORT:
            req = HIDIOCGFEATURE(data.size());
            break;
        default:
            HDF_LOGE("%{public}s: invalid report type", __func__);
            return HID_DDK_INVALID_PARAMETER;
    }

    int32_t res = ioctl(fd, req, data.data());
    if (res < 0) {
        HDF_LOGE("%{public}s ioctl failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    return HID_DDK_SUCCESS;
}

int32_t LinuxHidOsAdapter::GetReportDescriptor(int32_t fd, std::vector<uint8_t>& data, uint32_t& bytesRead)
{
    bytesRead = 0;

    uint32_t descSize = 0;
    int32_t ret = ioctl(fd, HIDIOCGRDESCSIZE, &descSize);
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl(HIDIOCGRDESCSIZE) failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    struct hidraw_report_descriptor desc;
    (void)memset_s(&desc, sizeof(desc), 0x0, sizeof(desc));

    desc.size = descSize;
    ret = ioctl(fd, HIDIOCGRDESC, &desc);
    if (ret < 0) {
        HDF_LOGE("%{public}s ioctl(HIDIOCGRDESC) failed, errno=%{public}d", __func__, errno);
        return HID_DDK_IO_ERROR;
    }

    uint32_t tempSize = desc.size < data.size() ? desc.size : data.size();
    ret = memcpy_s(data.data(), data.size(), desc.value, tempSize);
    if (ret < 0) {
        HDF_LOGE("%{public}s memcpy_s failed, ret=%{public}d, data.size=%{public}d, tempSize=%{public}d", __func__,
            ret, data.size(), tempSize);
        return HID_DDK_MEMORY_ERROR;
    }

    bytesRead = tempSize;

    return HID_DDK_SUCCESS;
}

} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS
