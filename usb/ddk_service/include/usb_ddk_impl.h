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
#ifndef USB_DDK_IMPL_H
#define USB_DDK_IMPL_H
#include "ddk_pnp_listener_mgr.h"
#include "hdf_log.h"
#include "iusb_ddk.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#define MAX_NOTIFICATION_FILTER_NUM 20
struct ListenerPrivInfo {
    struct INotificationCallback *cb;
};

int OnUsbDdkEventReceived(void *priv, uint32_t id, struct HdfSBuf *data);

// 32 means size of uint32_t
#define GET_BUS_NUM(devHandle)          ((uint8_t)((devHandle) >> 32))
#define GET_DEV_NUM(devHandle)          ((uint8_t)((devHandle) & 0xf))
#define USB_RECIP_MASK                  0x1F
#define GET_CTRL_REQ_RECIP(requestType) ((requestType) & USB_RECIP_MASK)
#define TRANS_DIRECTION_OFFSET          7
#define GET_CTRL_REQ_DIR(requestType)   ((requestType) >> TRANS_DIRECTION_OFFSET)
#define REQ_TYPE_OFFERT                 5
#define REQ_TYPE_MASK                   0x3
#define GET_CTRL_REQ_TYPE(requestType)  (((requestType) >> REQ_TYPE_OFFERT) & REQ_TYPE_MASK)

#define MAX_BUFF_SIZE         16384
#define MAX_CONTROL_BUFF_SIZE 1024
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // USB_DDK_IMPL_H