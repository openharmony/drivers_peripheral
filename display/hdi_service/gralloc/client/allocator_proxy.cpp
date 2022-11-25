/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "allocator_proxy.h"
#include <message_parcel.h>
#include "buffer_handle_parcel.h"
#include "iremote_object.h"
#include "iservmgr_hdi.h"
#include "parcel_utils.h"
#include "unistd.h"
#include "refbase.h"

#define HDF_LOG_TAG HDI_DISP_PROXY

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {
sptr<IDisplayAllocator> IDisplayAllocator::Get(const char *serviceName)
{
    constexpr uint32_t sleepTime = 10000;
    constexpr uint32_t waitSvcTimeout = 1000;
    constexpr uint32_t waitSvcMgrTimeout = 10;
    constexpr uint32_t printPeriod = 100;
    using namespace OHOS::HDI::ServiceManager::V1_0;

    static sptr<IServiceManager> servMgr = IServiceManager::Get();
    uint32_t cnt = 0;
    while (servMgr == nullptr) {
        if (cnt > waitSvcMgrTimeout) {
            HDF_LOGE("%{public}s: wait IServiceManager timeout cnt:%{public}u", __func__, cnt);
            return nullptr;
        }
        usleep(sleepTime);  // 10 ms
        servMgr = IServiceManager::Get();
        cnt++;
        HDF_LOGI("%{public}s: IServiceManager cnt:%{public}u", __func__, cnt);
    }
    HDF_LOGI("%{public}s: get IServiceManager success cnt:%{public}u", __func__, cnt);

    cnt = 0;
    sptr<IRemoteObject> remote = servMgr->GetService(serviceName);
    while (remote == nullptr) {
        if (cnt > waitSvcTimeout) {
            HDF_LOGE("%{public}s: wait service:%{public}s timeout cnt:%{public}u", __func__, serviceName, cnt);
            return nullptr;
        }
        usleep(sleepTime);  // 10 ms
        remote = servMgr->GetService(serviceName);
        if (((cnt++) % printPeriod) == 0) {
            HDF_LOGI("%{public}s: get service:%{public}s cnt:%{public}u", __func__, serviceName, cnt);
        }
    }
    HDF_LOGI("%{public}s: get service:%{public}s success cnt:%{public}u", __func__, serviceName, cnt);

    sptr<AllocatorProxy> hostSptr = iface_cast<AllocatorProxy>(remote);
    if (hostSptr == nullptr) {
        HDF_LOGE("%{public}s: IServiceManager GetService null ptr", __func__);
        return nullptr;
    }
    HDF_LOGE("%{public}s: GetService %{public}s ok", __func__, serviceName);
    return hostSptr;
}

int32_t AllocatorProxy::AllocMem(const AllocInfo &info, BufferHandle *&handle)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(AllocatorProxy::GetDescriptor())) {
        return HDF_FAILURE;
    }
    auto ret = ParcelUtils::PackAllocInfo(data, &info);
    if (ret != DISPLAY_SUCCESS) {
        return ret;
    }
    int32_t retCode = Remote()->SendRequest(CMD_REMOTE_ALLOCATOR_ALLOCMEM, data, reply, option);
    if (retCode != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, error code is %{public}x", __func__, retCode);
        return retCode;
    }

    retCode = reply.ReadInt32();
    if (retCode != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Read return code failed, error code is %{public}x", __func__, retCode);
        return retCode;
    }

    auto retHandle = ReadBufferHandle(reply);
    if (retHandle != nullptr) {
        handle = retHandle;
        retCode = DISPLAY_SUCCESS;
    } else {
        retCode = DISPLAY_NULL_PTR;
    }
    return retCode;
}
} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS
