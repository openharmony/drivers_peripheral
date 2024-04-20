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

#include "camera_fileformat.h"

namespace OHOS::Camera {

CameraFileFormat::CameraFileFormat() {}
CameraFileFormat::~CameraFileFormat() {}

void CameraFileFormat::CameraGetCurrentFormat(struct CameraFeature &feature, std::vector<CameraCtrl> &fmtDesc,
    struct CameraFmtDesc &enumFmtDesc)
{
    struct CameraFrmRatioDesc fraMival = {};
    constexpr uint32_t fmtMax = 1;
    for (int k = 0; k < fmtMax; ++k) {
        fraMival.index = k;
        fraMival.pixelFormat = frmSize.pixelFormat;
        fraMival.width = frmSize.width;
        fraMival.height = frmSize.height;
        ret = Enumfrmivale(feature, fraMival);
        if (ret == 0) {
            break;
        }
        CameraCtrl currentFormat = {};
        strncpy_s(currentFormat.fmtdesc.description, NAME_SIZE, enumFmtDesc.description, NAME_SIZE);
        currentFormat.fmtdesc.pixelFormat = enumFmtDesc.pixelFormat;
        currentFormat.fmtdesc.width = frmSize.width;
        currentFormat.fmtdesc.height = frmSize.height;
        currentFormat.fmtdesc.fps.numerator = fraMival.numerator;
        currentFormat.fmtdesc.fps.denominator = fraMival.denominator;
        fmtDesc.push_back(currentFormat);
    }
}

RetCode CameraFileFormat::CameraSearchFormat(struct CameraFeature feature, std::vector<CameraCtrl> &fmtDesc)
{
    int32_t i;
    int32_t j;
    int32_t ret;
    constexpr uint32_t fmtMax = 1;
    struct CameraFmtDesc enumFmtDesc = {};
    struct CameraFrmSizeDesc frmSize = {};

    for (i = 0; i < fmtMax; ++i) {
        enumFmtDesc.index = i;
        ret = EnumFmtDesc(feature, enumFmtDesc);
        if (ret != 0) {
            break;
        }
        for (j = 0; j < fmtMax; ++j) {
            frmSize.index = j;
            frmSize.pixelFormat = enumFmtDesc.pixelFormat;
            ret = EnumFrmsize(feature, frmSize);
            if (ret != 0) {
                break;
            }
            CameraGetCurrentFormat(feature, fmtDesc, enumFmtDesc);
        }
    }
    if (i == 0) {
        CAMERA_LOGE("no valid supported formats\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraFileFormat::CameraGetFmtDescs(struct CameraFeature feature, std::vector<CameraCtrl> &fmtDesc)
{
    int32_t ret;
    std::vector<CameraCtrl>().swap(fmtDesc);

    ret = CameraSearchFormat(feature, fmtDesc);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraSearchFormat failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraOpenDevice(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, false);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_OPEN_CAMERA, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_OPEN_CAMERA failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraCloseDevice(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, false);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_CLOSE_CAMERA, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_CLOSE_CAMERA failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraSetFormat(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    CAMERA_LOGD("set pixelFormat = %{public}d, set width = %{public}d, set height = %{public}d\n",
        ctrl.fmtdesc.pixelFormat, ctrl.fmtdesc.width, ctrl.fmtdesc.height);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.fmtdesc.pixelFormat);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.fmtdesc.width);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.fmtdesc.height);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_SET_FMT, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_SET_FMT failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraGetFormat(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.control.id);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_GET_FMT, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_GET_FMT failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.pixelFormat));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.width));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.height));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.sizeImage));
    CAMERA_LOGD("get pixelFormat = %{public}d, get width = %{public}d, get height = %{public}d, "
        "get sizeImage = %{public}d\n", ctrl.fmtdesc.pixelFormat, ctrl.fmtdesc.width, ctrl.fmtdesc.height,
        ctrl.fmtdesc.sizeImage);
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(respData);

    return ret;
}

RetCode CameraFileFormat::CameraSetCrop(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteInt32(reqData, ctrl.crop.left);
    isFailed |= !HdfSbufWriteInt32(reqData, ctrl.crop.top);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.crop.width);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.crop.height);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_SET_CROP, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_SET_CROP failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraGetCrop(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_GET_CROP, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_GET_CROP failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadInt32(respData, &(ctrl.crop.left));
    isFailed |= !HdfSbufReadInt32(respData, &(ctrl.crop.top));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.crop.width));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.crop.height));
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(respData);

    return ret;
}

RetCode CameraFileFormat::CameraSetFPS(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.fmtdesc.fps.denominator);
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.fmtdesc.fps.numerator);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_SET_FPS, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_SET_FPS failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraFileFormat::CameraGetFPS(struct CameraFeature feature, CameraCtrl &ctrl)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_GET_FPS, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_GET_FPS failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.fps.numerator));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.fmtdesc.fps.denominator));
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(respData);

    return ret;
}

int CameraFileFormat::EnumFmtDesc(struct CameraFeature feature, struct CameraFmtDesc &enumFmtDesc)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteInt32(reqData, CAMERA_CMD_ENUM_FMT);
    isFailed |= !HdfSbufWriteInt32(reqData, enumFmtDesc.index);
    CHECK_RETURN_RESULT(isFailed);
    ret = SendCameraCmd(CMD_ENUM_FMT, reqData, respData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CAMERA_CMD_ENUM_FMT SendCameraCmd failed, ret = %{public}d\n", ret);
        return RC_ERROR;
    }

    isFailed |= strncpy_s(enumFmtDesc.description, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint32(respData, &(enumFmtDesc.pixelFormat));
    CHECK_RETURN_RESULT(isFailed);

    HdfSbufRecycle(reqData);
    HdfSbufRecycle(respData);

    CAMERA_LOGD("Supported format with description = %{public}s\n\n", enumFmtDesc.description);
    return ret;
}

int CameraFileFormat::EnumFrmsize(struct CameraFeature feature, struct CameraFrmSizeDesc &frmSize)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteInt32(reqData, CAMERA_CMD_ENUM_FRAMESIZES);
    isFailed |= !HdfSbufWriteInt32(reqData, frmSize.index);
    isFailed |= !HdfSbufWriteUint32(reqData, frmSize.pixelFormat);
    CHECK_RETURN_RESULT(isFailed);
    ret = SendCameraCmd(CMD_ENUM_FMT, reqData, respData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CAMERA_CMD_ENUM_FRAMESIZES SendCameraCmd failed, ret = %{public}d\n", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(frmSize.width));
    isFailed |= !HdfSbufReadUint32(respData, &(frmSize.height));
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(reqData);
    HdfSbufRecycle(respData);

    return ret;
}

int CameraFileFormat::Enumfrmivale(struct CameraFeature feature, struct CameraFrmRatioDesc &fraMival)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteInt32(reqData, CAMERA_CMD_ENUM_FRAMEINTERVALS);
    isFailed |= !HdfSbufWriteInt32(reqData, fraMival.index);
    isFailed |= !HdfSbufWriteUint32(reqData, fraMival.pixelFormat);
    isFailed |= !HdfSbufWriteInt32(reqData, fraMival.width);
    isFailed |= !HdfSbufWriteUint32(reqData, fraMival.height);
    CHECK_RETURN_RESULT(isFailed);
    ret = SendCameraCmd(CMD_ENUM_FMT, reqData, respData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CAMERA_CMD_ENUM_FRAMEINTERVALS SendCameraCmd failed, ret = %{public}d\n", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(fraMival.numerator));
    isFailed |= !HdfSbufReadUint32(respData, &(fraMival.denominator));
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(reqData);
    HdfSbufRecycle(respData);

    CAMERA_LOGD("frame interval: %{public}d, %{public}d\n", fraMival.numerator, fraMival.denominator);
    return ret;
}

} // namespace OHOS::Camera
