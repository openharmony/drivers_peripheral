/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef WLAN_EXTEND_VDI_CMD_H
#define WLAN_EXTEND_VDI_CMD_H

#include "v1_3/iwlan_interface.h"
#include "hdf_load_vdi.h"
#include "wifi_hal.h"

#define WLAN_EXTEND_VDI_LIBNAME "libhdi_wlan_impl.z.so"

struct WlanExtendInterfaceVdi {
    int32_t (*startChannelMeas)(struct IWlanInterface *self, const char *ifName,
        const struct MeasChannelParam *measChannelParam);
    int32_t (*getChannelMeasResult)(struct IWlanInterface *self, const char *ifName,
        struct MeasChannelResult *measChannelResult);
    int32_t (*sendCmdIoctl)(struct IWlanInterface *self, const char *ifName, int32_t cmdId,
        const int8_t *paramBuf, uint32_t paramBufLen);
    int32_t (*getCoexChannelList)(struct IWlanInterface *self, const char *ifName,
        uint8_t *paramBuf, uint32_t *paramBufLen);
    int32_t (*registerHid2dCallback)(Hid2dCallbackFunc func, const char *ifName);
    int32_t (*unregisterHid2dCallback)(Hid2dCallbackFunc func, const char *ifName);
    int32_t (*wifiConstruct)(void);
    int32_t (*wifiDestruct)(void);
};

struct VdiWrapperWlanExtend {
    struct HdfVdiBase base;
    struct WlanExtendInterfaceVdi *wlanExtendModule;
};
#endif
