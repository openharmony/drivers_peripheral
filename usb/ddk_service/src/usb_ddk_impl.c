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
#include "usb_ddk_impl.h"
#include "hdf_log.h"

#define HDF_LOG_TAG usb_ddk_impl

static enum NotificationType ToUsbDdkNotifyType(uint32_t id)
{
    switch (id) {
        case USB_PNP_NOTIFY_ADD_DEVICE:
            return USB_DEVICE_ATTACH;
        case USB_PNP_NOTIFY_REMOVE_DEVICE:
            return USB_DEVICE_DETACH;
        default:
            return USB_NOTIFICATION_UNKNOW;
    }
}

// Make sure the pointer is not empty before calling, and no double check is done here
static uint64_t MakeDevHandle(const struct UsbPnpNotifyMatchInfoTable *info)
{
    // 32 means the size if uint32_t
    return (uint64_t)info->busNum << 32 | (uint32_t)info->devNum;
}

int OnUsbDdkEventReceived(void *priv, uint32_t id, struct HdfSBuf *data)
{
    bool ifDevAttachOrDetach = (id == USB_PNP_NOTIFY_ADD_DEVICE) || (id == USB_PNP_NOTIFY_REMOVE_DEVICE);
    if (!ifDevAttachOrDetach) {
        HDF_LOGI("%{public}s recv event %{public}u", __func__, id);
        return HDF_SUCCESS;
    }

    if (data == NULL || priv == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbPnpNotifyMatchInfoTable *info = NULL;
    uint32_t infoSize = 0;
    bool flag = HdfSbufReadBuffer(data, (const void **)(&info), &infoSize);
    if (!flag || info == NULL) {
        HDF_LOGE("%{public}s: HdfSbufReadBuffer failed, flag=%{public}d", __func__, flag);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ListenerPrivInfo *privInfo = (struct ListenerPrivInfo *)priv;
    if (privInfo->cb == NULL || privInfo->cb->OnNotificationCallback == NULL) {
        HDF_LOGE("%{public}s: invalid callback", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return privInfo->cb->OnNotificationCallback(privInfo->cb, ToUsbDdkNotifyType(id), MakeDevHandle(info));
}
