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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "codec_image_config.h"
#include "codec_log_wrapper.h"
#include "v2_1/codec_image_stub.h"

using namespace OHOS::HDI::Codec::Image::V2_1;

struct HdfCodecImageHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t CodecImageDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfCodecImageHost = CONTAINER_OF(client->device->service, struct HdfCodecImageHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        CODEC_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        CODEC_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfCodecImageHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfCodecImageDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("driver init start");
    if (deviceObject->property == nullptr) {
        CODEC_LOGE("fail to get deviceObject property");
        return HDF_FAILURE;
    }
    CodecImageConfig::GetInstance()->Init(*(deviceObject->property));
    return HDF_SUCCESS;
}

static int HdfCodecImageDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("driver bind start");
    auto *hdfCodecImageHost = new (std::nothrow) HdfCodecImageHost;
    if (hdfCodecImageHost == nullptr) {
        CODEC_LOGE("failed to create create HdfCodecImageHost object");
        return HDF_FAILURE;
    }

    hdfCodecImageHost->ioService.Dispatch = CodecImageDriverDispatch;
    hdfCodecImageHost->ioService.Open = NULL;
    hdfCodecImageHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Codec::Image::V2_1::ICodecImage::Get(true);
    if (serviceImpl == nullptr) {
        CODEC_LOGE("failed to get of implement service");
        delete hdfCodecImageHost;
        return HDF_FAILURE;
    }

    hdfCodecImageHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Codec::Image::V2_1::ICodecImage::GetDescriptor());
    if (hdfCodecImageHost->stub == nullptr) {
        CODEC_LOGE("failed to get stub object");
        delete hdfCodecImageHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfCodecImageHost->ioService;
    return HDF_SUCCESS;
}

static void HdfCodecImageDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("driver release start");
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfCodecImageHost = CONTAINER_OF(deviceObject->service, struct HdfCodecImageHost, ioService);
    if (hdfCodecImageHost != nullptr) {
        delete hdfCodecImageHost;
    }
}

static struct HdfDriverEntry g_CodecImageDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "libcodec_image_service",
    .Bind = HdfCodecImageDriverBind,
    .Init = HdfCodecImageDriverInit,
    .Release = HdfCodecImageDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_CodecImageDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
