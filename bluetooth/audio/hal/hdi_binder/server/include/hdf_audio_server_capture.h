/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HDF_AUDIO_SERVER_CAPTURE_H
#define HDF_AUDIO_SERVER_CAPTURE_H

#include "hdf_device_desc.h"
namespace OHOS::HDI::Audio_Bluetooth {
int32_t HdiServiceCreateCapture(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureDestory(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureStart(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureStop(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCapturePause(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureResume(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureFlush(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceRenderGetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceRenderSetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceCaptureCaptureFrame(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
}
#endif
