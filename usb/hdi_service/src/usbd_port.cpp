/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "usbd_port.h"
#include "default_config.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "usbd_function.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
UsbdPort &UsbdPort::GetInstance()
{
    static UsbdPort instance;
    return instance;
}

int32_t UsbdPort::IfCanSwitch(int32_t portId, int32_t powerRole, int32_t dataRole)
{
    if (portId != DEFAULT_PORT_ID) {
        HDF_LOGE("%{public}s: portId error", __func__);
        return HDF_FAILURE;
    }

    if (powerRole <= POWER_ROLE_NONE || powerRole >= POWER_ROLE_MAX) {
        HDF_LOGE("%{public}s: powerRole error", __func__);
        return HDF_FAILURE;
    }

    if (dataRole <= DATA_ROLE_NONE || dataRole >= DATA_ROLE_MAX) {
        HDF_LOGE("%{public}s: dataRole error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdPort::WritePortFile(int32_t powerRole, int32_t dataRole, int32_t mode)
{
    std::string modeStr;

    if (mode == PORT_MODE_HOST || mode == PORT_MODE_DEVICE) {
        switch (mode) {
            case PORT_MODE_HOST:
                modeStr = PORT_MODE_HOST_STR;
                UsbdFunction::UsbdSetFunction(USB_FUNCTION_NONE);
                break;
            case PORT_MODE_DEVICE:
                modeStr = PORT_MODE_DEVICE_STR;
                break;
            default:
                break;
        }
    }
    if (modeStr.empty()) {
        HDF_LOGE("%{public}s: modeStr error", __func__);
        return HDF_FAILURE;
    }

    uint32_t len = modeStr.size();
    int32_t fd = open(PORT_FILE_PATH, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        HDF_LOGE("%{public}s: file open error fd = %{public}d", __func__, fd);
        return HDF_FAILURE;
    }

    int32_t ret = write(fd, modeStr.c_str(), len);
    close(fd);
    if (ret < 0) {
        HDF_LOGE("%{public}s: write  error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdPort::SetPortInit(int32_t portId, int32_t powerRole, int32_t dataRole)
{
    int32_t mode = PORT_MODE_DEVICE;
    if (IfCanSwitch(portId, powerRole, dataRole)) {
        return HDF_FAILURE;
    }

    if (powerRole == POWER_ROLE_SOURCE && dataRole == DATA_ROLE_HOST) {
        mode = PORT_MODE_HOST;
    }

    if (powerRole == POWER_ROLE_SINK && dataRole == DATA_ROLE_DEVICE) {
        mode = PORT_MODE_DEVICE;
    }

    if (WritePortFile(powerRole, dataRole, mode)) {
        return HDF_FAILURE;
    }
    currentPortInfo_.portId = portId;
    currentPortInfo_.powerRole = powerRole;
    currentPortInfo_.dataRole = dataRole;
    currentPortInfo_.mode = mode;
    if (currentPortInfo_.mode == PORT_MODE_DEVICE) {
        UsbdFunction::UsbdSetFunction(USB_FUNCTION_HDC);
    }
    return HDF_SUCCESS;
}

int32_t UsbdPort::SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
    UsbdSubscriber *usbdSubscribers, uint32_t len)
{
    int32_t ret = SetPortInit(portId, powerRole, dataRole);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetPortInit failed! ret:%{public}d", __func__, ret);
        return ret;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (usbdSubscribers[i].subscriber != nullptr) {
            usbdSubscribers[i].subscriber->PortChangedEvent(currentPortInfo_);
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPort::QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    portId = currentPortInfo_.portId;
    powerRole = currentPortInfo_.powerRole;
    dataRole = currentPortInfo_.dataRole;
    mode = currentPortInfo_.mode;
    return HDF_SUCCESS;
}

int32_t UsbdPort::UpdatePort(int32_t mode, const sptr<IUsbdSubscriber> &subscriber)
{
    switch (mode) {
        case PORT_MODE_HOST:
            currentPortInfo_.powerRole = POWER_ROLE_SOURCE;
            currentPortInfo_.dataRole = DATA_ROLE_HOST;
            currentPortInfo_.mode = PORT_MODE_HOST;
            break;
        case PORT_MODE_DEVICE:
            currentPortInfo_.powerRole = POWER_ROLE_SINK;
            currentPortInfo_.dataRole = DATA_ROLE_DEVICE;
            currentPortInfo_.mode = PORT_MODE_DEVICE;
            break;
        default:
            HDF_LOGE("%{public}s invalid mode:%{public}d", __func__, mode);
            return HDF_FAILURE;
    }

    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s subscriber is nullptr", __func__);
        return HDF_FAILURE;
    }
    subscriber->PortChangedEvent(currentPortInfo_);
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
