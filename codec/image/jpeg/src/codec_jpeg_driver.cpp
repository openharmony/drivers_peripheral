/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "codec_image_config.h"
#include "codec_image_log.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_sbuf_ipc.h"
#include "v1_0/codec_image_jpeg_stub.h"

using namespace OHOS::HDI::Codec::Image::V1_0;
namespace {
    struct HdfCodecJpegHost {
        struct IDeviceIoService ioService;
        OHOS::sptr<OHOS::IRemoteObject> stub;
    };
}

static int32_t CodecJpegDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
                                       struct HdfSBuf *reply)
{
    auto *hdfCodecJpegHost =
        CONTAINER_OF(client->device->service, struct HdfCodecJpegHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    int32_t ret = SbufToParcel(data, &dataParcel);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("invalid data sbuf object to dispatch, error [%{public}d]", ret);
        return HDF_ERR_INVALID_PARAM;
    }
    
    ret = SbufToParcel(reply, &replyParcel);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("invalid reply sbuf object to dispatch, error [%{public}d]", ret);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfCodecJpegHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfCodecJpegDriverInit(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecJpegDriverInit enter");
    CodecImageConfig::GetInstance()->Init(*(deviceObject->property));
    return HDF_SUCCESS;
}

static int HdfCodecJpegDriverBind(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecJpegDriverBind enter");

    auto *hdfCodecJpegHost = new (std::nothrow) HdfCodecJpegHost;
    if (hdfCodecJpegHost == nullptr) {
        CODEC_LOGE("failed to create create HdfCodecJpegHost object");
        return HDF_FAILURE;
    }

    hdfCodecJpegHost->ioService.Dispatch = CodecJpegDriverDispatch;
    hdfCodecJpegHost->ioService.Open = NULL;
    hdfCodecJpegHost->ioService.Release = NULL;

    auto serviceImpl = ICodecImageJpeg::Get(true);
    if (serviceImpl == nullptr) {
        CODEC_LOGE("failed to get of implement service");
        delete hdfCodecJpegHost;
        return HDF_FAILURE;
    }

    hdfCodecJpegHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, ICodecImageJpeg::GetDescriptor());
    if (hdfCodecJpegHost->stub == nullptr) {
        CODEC_LOGE("failed to get stub object");
        delete hdfCodecJpegHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfCodecJpegHost->ioService;
    return HDF_SUCCESS;
}

static void HdfCodecJpegDriverRelease(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecJpegDriverRelease enter");
    if (deviceObject->service == nullptr) {
        CODEC_LOGE("HdfCodecJpegDriverRelease not initted");
        return;
    }

    auto *hdfCodecJpegHost =
        CONTAINER_OF(deviceObject->service, struct HdfCodecJpegHost, ioService);
    delete hdfCodecJpegHost;
}

static struct HdfDriverEntry g_codecJpegDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "libcodec_jpeg_driver.z.so",
    .Bind = HdfCodecJpegDriverBind,
    .Init = HdfCodecJpegDriverInit,
    .Release = HdfCodecJpegDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_codecJpegDriverEntry);
#ifndef __cplusplus
}
#endif
