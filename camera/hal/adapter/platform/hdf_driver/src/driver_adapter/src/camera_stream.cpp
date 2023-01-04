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

#include "camera_stream.h"

namespace OHOS::Camera {

CameraStreams::CameraStreams()
{
}

CameraStreams::~CameraStreams() {}

RetCode CameraStreams::CameraStreamOn(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_STREAM_ON, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_STREAM_ON failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraStreams::CameraStreamOff(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_STREAM_OFF, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_STREAM_OFF failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

} // namespace OHOS::Camera
