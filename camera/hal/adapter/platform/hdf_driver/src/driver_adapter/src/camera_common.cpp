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

#include "camera_common.h"

namespace OHOS::Camera {

const std::string DRIVER_SERVICE_NAME = "hdfcamera";

struct HdfIoService *g_cameraService = nullptr;
static struct HdfDevEventlistener g_cameraDevEventListener;
static bool g_isHasRegisterListener = false;

static void CameraUvcEventResultProcess(struct HdfSBuf *data)
{
    int32_t uvcState;
    const char *cameraName = nullptr;
    const char *uvcDeviceName = nullptr;
    const char *uvcStreamName = nullptr;

    if (!HdfSbufReadInt32(data, &uvcState)) {
        CAMERA_LOGE("fail to get uvcState!");
        return;
    }

    cameraName = HdfSbufReadString(data);
    if (cameraName == NULL) {
        CAMERA_LOGE("%s: fail to get cameraName!", __func__);
        return;
    }

    uvcDeviceName = HdfSbufReadString(data);
    if (uvcDeviceName == NULL) {
        CAMERA_LOGE("%s: fail to get uvcDeviceName!", __func__);
        return;
    }

    uvcStreamName = HdfSbufReadString(data);
    if (uvcStreamName == NULL) {
        CAMERA_LOGE("%s: fail to get uvcStreamName!", __func__);
        return;
    }
    CAMERA_LOGD("uvcState = %{public}d, cameraName = %{public}s, cameraName = %{public}s, cameraName = %{public}s",
        uvcState, cameraName, uvcDeviceName, uvcStreamName);
}

static int32_t CameraMsgRegisterEventListener(struct HdfDevEventlistener *listener)
{
    if (g_cameraService == nullptr || listener == nullptr) {
        return HDF_FAILURE;
    }
    if (HdfDeviceRegisterEventListener(g_cameraService, listener) != HDF_SUCCESS) {
        CAMERA_LOGE("fail to register event listener, line: %{public}d", __LINE__);
        return HDF_FAILURE;
    }
    g_isHasRegisterListener = true;
    return HDF_SUCCESS;
}

static int OnCameraEvents(struct HdfDevEventlistener *listener, struct HdfIoService *service,
    uint32_t eventId, struct HdfSBuf *data)
{
    (void)listener;
    (void)service;

    if (data == nullptr) {
        CAMERA_LOGE("param ptr is nullptr, line: %{public}d", __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (eventId == CAMERA_UVC_EVENT) {
        CameraUvcEventResultProcess(data);
    }

    return HDF_SUCCESS;
}

int32_t CameraDriverClientInit(void)
{
    int32_t ret;

    if (g_cameraService == nullptr) {
        g_cameraService = HdfIoServiceBind(DRIVER_SERVICE_NAME.c_str());
    }
    if (g_cameraService == nullptr) {
        CAMERA_LOGE("fail to get remote service!");
        return HDF_FAILURE;
    }
    g_cameraDevEventListener.onReceive = OnCameraEvents;
    if (g_isHasRegisterListener) {
        CAMERA_LOGE("has register listener!");
        return HDF_SUCCESS;
    }
    ret = CameraMsgRegisterEventListener(&g_cameraDevEventListener);
    if (ret != HDF_SUCCESS) {
        CAMERA_LOGE("register event listener failed, line: %{public}d, ret = %{public}d", __LINE__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

RetCode SendCameraCmd(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData)
{
    int32_t ret;

    if (reqData == nullptr) {
        CAMERA_LOGE("SendCameraCmd reqData ptr is nullptr!");
        return RC_ERROR;
    }

    if (g_cameraService == nullptr || g_cameraService->dispatcher == nullptr ||
        g_cameraService->dispatcher->Dispatch == nullptr) {
        CAMERA_LOGE("bad remote service found!");
        return RC_ERROR;
    }

    ret = g_cameraService->dispatcher->Dispatch(&g_cameraService->object, cmd, reqData, respData);
    if (ret != RC_OK) {
        CAMERA_LOGE("SendCameraCmd failed, cmd = %{public}d, ret = %{public}d", cmd, ret);
        return RC_ERROR;
    }
    return RC_OK;
}

int32_t SendDeviceInfo(struct HdfSBuf *reqData, struct CameraFeature feature, bool state)
{
    bool isFailed = false;
    if (state) {
        isFailed |= !HdfSbufWriteInt32(reqData, feature.type);
    }
    isFailed |= !HdfSbufWriteInt32(reqData, feature.permissionId);
    isFailed |= !HdfSbufWriteString(reqData, feature.deviceName);
    isFailed |= !HdfSbufWriteString(reqData, feature.driverName);
    CHECK_RETURN_RESULT(isFailed);
    return RC_OK;
}

} // namespace OHOS::Camera