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

#include "serial_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>

#include "hisysevent.h"
#include "hitrace_meter.h"
#include "usbd_wrapper.h"
#ifdef LINUX_SERIAL
#include "linux_serial.h"
#else
#include "libusb_serial.h"
#endif

#define HDF_LOG_TAG    serial_interface_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

extern "C" ISerialInterface* SerialInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Usb::Serial::V1_0::SerialImpl;
    SerialImpl *service = new (std::nothrow) SerialImpl();
    if (service == nullptr) {
        return nullptr;
    }
    
    return service;
}

SerialImpl::SerialImpl()
{
    HDF_LOGI("into SerialImpl construct");
#ifdef LINUX_SERIAL
    LinuxSerial::GetInstance();
#else
    LibusbSerial::GetInstance();
#endif
}

SerialImpl::~SerialImpl()
{
    HDF_LOGE("%{public}s:~SerialImpl", __func__);
}

int32_t SerialImpl::SerialOpen(int32_t portId)
{
    HDF_LOGI("SerialImpl::SerialOpen start");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialOpen(portId);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialOpen(portId);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialOpen failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialClose(int32_t portId)
{
    HDF_LOGI("SerialImpl::SerialClose start");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialClose(portId);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialClose(portId);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialClose failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
{
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_HDF, "SerialRead");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialRead(portId, data, size, timeout);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialRead(portId, data, size, timeout);
#endif
    FinishTrace(HITRACE_LEVEL_INFO, HITRACE_TAG_HDF);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialRead failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
{
    StartTrace(HITRACE_LEVEL_INFO, HITRACE_TAG_HDF, "SerialWrite");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialWrite(portId, data, size, timeout);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialWrite(portId, data, size, timeout);
#endif
    FinishTrace(HITRACE_LEVEL_INFO, HITRACE_TAG_HDF);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialWrite failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialSetAttribute(int32_t portId, const SerialAttribute& attribute)
{
    HDF_LOGI("SerialImpl::SerialSetAttribute start");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialSetAttribute(portId, attribute);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialSetAttribute(portId, attribute);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialSetAttribute failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialGetAttribute(int32_t portId, SerialAttribute& attribute)
{
    HDF_LOGI("SerialImpl::SerialGetAttribute start");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialGetAttribute(portId, attribute);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialGetAttribute(portId, attribute);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialGetAttribute failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}

int32_t SerialImpl::SerialGetPortList(std::vector<SerialPort>& portList)
{
    HDF_LOGI("SerialImpl::SerialGetPortList start");
#ifdef LINUX_SERIAL
    int32_t ret = LinuxSerial::GetInstance().SerialGetPortList(portList);
#else
    int32_t ret = LibusbSerial::GetInstance().SerialGetPortList(portList);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SerialGetPortList failed, ret:%{public}d", __func__, ret);
    }

    return ret;
}
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
