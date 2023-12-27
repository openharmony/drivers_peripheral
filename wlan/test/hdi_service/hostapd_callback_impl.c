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

#include "hostapd_callback_impl.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>

static int32_t HostapdCallbackStaJoin(struct IHostapdCallback *self,
    const struct HdiApCbParm *apCbParm, const char *ifName)
{
    (void)self;
    if (apCbParm == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("HostapdCallbackStaJoin: content=%{public}s, id=%{public}d", apCbParm->content, apCbParm->id);
    return HDF_SUCCESS;
}

static int32_t HostapdCallbackApState(struct IHostapdCallback *self,
    const struct HdiApCbParm *apCbParm, const char *ifName)
{
    (void)self;
    if (apCbParm == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("HostapdCallbackApState: content=%{public}s, id=%{public}d", apCbParm->content, apCbParm->id);
    return HDF_SUCCESS;
}

struct IHostapdCallback *HostapdCallbackServiceGet(void)
{
    struct HostapdCallbackService *service =
        (struct HostapdCallbackService *)OsalMemCalloc(sizeof(struct HostapdCallbackService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc HostapdCallbackService obj failed!", __func__);
        return NULL;
    }

    service->interface.OnEventStaJoin = HostapdCallbackStaJoin;
    service->interface.OnEventApState = HostapdCallbackApState;
    return &service->interface;
}

void HostapdCallbackServiceRelease(struct IHostapdCallback *instance)
{
    struct HostapdCallbackService *service = (struct HostapdCallbackService *)instance;
    if (service == NULL) {
        return;
    }
    OsalMemFree(service);
}
