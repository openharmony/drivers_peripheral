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

#include "allocator_service_stub.h"
#include "buffer_handle_parcel.h"
#include "buffer_handle_utils.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hdf_sbuf_ipc.h"
#include "parcel_utils.h"

#define HDF_LOG_TAG HDI_DISP_STUB

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {

AllocatorServiceStub::AllocatorServiceStub()
{
    if (GrallocInitialize(&grallocFuncs_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: gralloc init failed", __func__);
    }
}

AllocatorServiceStub::~AllocatorServiceStub()
{
    if (GrallocUninitialize(grallocFuncs_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: gralloc uninit failed", __func__);
    }
}

int32_t AllocatorServiceStub::AllocMem(MessageParcel &data,
    MessageParcel &reply, MessageOption &option) const
{
    AllocInfo info;
    if (ParcelUtils::UnpackAllocInfo(data, &info) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UnpackAllocInfo failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    BufferHandle *buffer = nullptr;
    int32_t errCode = grallocFuncs_->AllocMem(&info, &buffer);

    if (!reply.WriteInt32(errCode)) {
        HDF_LOGE("AllocMem: write reply failed!");
        return HDF_FAILURE;
    }

    if (errCode != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:  call failed", __func__);
        return errCode;
    }

    if (WriteBufferHandle(reply, *buffer) != true) {
        HDF_LOGE("%{public}s: WriteBufferHandle failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    FreeBufferHandle(buffer);
    return HDF_SUCCESS;
}

int32_t AllocatorServiceStub::OnRemoteRequest(int cmdId,
    MessageParcel &data, MessageParcel &reply, MessageOption &option) const
{
    switch (cmdId) {
        case CMD_ALLOCATOR_ALLOCMEM:
            return AllocMem(data, reply, option);
        default: {
            HDF_LOGE("%{public}s: not support cmd", __func__);
            return HDF_ERR_INVALID_PARAM;
        }
    }
    return HDF_SUCCESS;
}

} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS

using namespace OHOS::HDI::Display::V1_0;

void *AllocatorServiceStubInstance()
{
    return reinterpret_cast<void *>(new AllocatorServiceStub());
}

void AllocatorServiceStubRelease(void *stubObj)
{
    delete reinterpret_cast<AllocatorServiceStub *>(stubObj);
    stubObj = nullptr;
}

int32_t AllocatorServiceOnRemoteRequest(void *stub, int cmdId, struct HdfSBuf &data, struct HdfSBuf &reply)
{
    if (stub == nullptr) {
        HDF_LOGE("%{public}s: stub is nullptr", __func__);
        return HDF_FAILURE;
    }

    AllocatorServiceStub *AllocatorStub = reinterpret_cast<AllocatorServiceStub *>(stub);
    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;

    if (SbufToParcel(&reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (SbufToParcel(&data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    OHOS::MessageOption option;
    return AllocatorStub->OnRemoteRequest(cmdId, *dataParcel, *replyParcel, option);
}
