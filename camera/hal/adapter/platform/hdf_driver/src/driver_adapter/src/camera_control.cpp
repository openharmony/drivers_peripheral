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

#include "camera_control.h"

namespace OHOS::Camera {

CameraControl::CameraControl() {}
CameraControl::~CameraControl() {}

RetCode CameraControl::CameraPowerUp(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_POWER_UP, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_POWER_UP failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraControl::CameraPowerDown(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_POWER_DOWN, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_POWER_DOWN failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraControl::CameraQueryConfig(struct CameraFeature feature, CameraCtrl &ctrl)
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

    ret = SendCameraCmd(CMD_QUERY_CONFIG, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_QUERY_CONFIG failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.ctrlInfo.ctrlId));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.ctrlInfo.max));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.ctrlInfo.min));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.ctrlInfo.step));
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.ctrlInfo.defaultValue));
    CHECK_RETURN_RESULT(isFailed);
    CAMERA_LOGD("get ctrlId = %{public}d, get max = %{public}d, get min = %{public}d, get step = %{public}d, "
        "get defaultValue = %{public}d\n", ctrl.control.ctrlInfo.ctrlId, ctrl.control.ctrlInfo.max,
        ctrl.control.ctrlInfo.min, ctrl.control.ctrlInfo.step, ctrl.control.ctrlInfo.defaultValue);
    HdfSbufRecycle(respData);

    return ret;
}

RetCode CameraControl::CameraSetConfig(struct CameraFeature feature, CameraCtrl &ctrl)
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
    isFailed |= !HdfSbufWriteUint32(reqData, ctrl.control.value);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_SET_CONFIG, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_SET_CONFIG failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraControl::CameraGetConfig(struct CameraFeature feature, CameraCtrl &ctrl)
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

    ret = SendCameraCmd(CMD_GET_CONFIG, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_GET_CONFIG failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    isFailed |= !HdfSbufReadUint32(respData, &(ctrl.control.value));
    CHECK_RETURN_RESULT(isFailed);
    HdfSbufRecycle(respData);

    return ret;
}

RetCode CameraControl::CameraGetConfigs(struct CameraFeature feature, std::vector<CameraCtrl> &ctrl, int count)
{
    int32_t ret;
    CameraCtrl ctrls = {};

    if (count != ctrl.size()) {
        CAMERA_LOGE("count != ctrl.size()\n");
        return RC_ERROR;
    }

    for (auto itr = ctrl.begin(); itr != ctrl.end(); itr++) {
        ctrls.control.id = itr->control.id;
        ret = CameraGetConfig(feature, ctrls);
        if (ret != RC_OK) {
            CAMERA_LOGE("error: CameraGetConfig failed, id = %{public}d\n", itr->control.id);
            continue;
        }
        itr->control.value = ctrls.control.value;
    }

    return RC_OK;
}

RetCode CameraControl::CameraSetConfigs(struct CameraFeature feature, std::vector<CameraCtrl> &ctrl, int count)
{
    int32_t ret;
    CameraCtrl ctrls = {};

    if (count != ctrl.size()) {
        CAMERA_LOGE("count != ctrl.size()\n");
        return RC_ERROR;
    }

    for (auto itr = ctrl.begin(); itr != ctrl.end(); itr++) {
        ctrls.control.id = itr->control.id;
        ctrls.control.value = itr->control.value;
        ret = CameraSetConfig(feature, ctrls);
        if (ret != RC_OK) {
            CAMERA_LOGE("error: CameraSetConfig failed, id = %{public}d\n", itr->control.id);
            continue;
        }
    }
    return RC_OK;
}

RetCode CameraControl::CameraEnumDevices(struct CameraFeature feature, struct DeviceaInfo &device)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);
    ret = SendCameraCmd(CMD_ENUM_DEVICES, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_ENUM_DEVICES failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    ret = ReadDeviceSbufData(feature.type, respData, device);
    CHECK_RETURN_RESULT(ret);
    HdfSbufRecycle(respData);

    return ret;
}

RetCode CameraControl::CameraGetAbility(struct CameraFeature feature)
{
    int32_t ret;
    struct CameraCapability ability = {};

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_GET_ABILITY, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_GET_ABILITY failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    ret = ReadAbilitySbufData(respData, ability);
    CHECK_RETURN_RESULT(ret);

    HdfSbufRecycle(respData);
    return ret;
}

RetCode CameraControl::CameraMatchDevice(struct CameraFeature feature)
{
    return CameraGetAbility(feature);
}

int CameraControl::ReadAbilitySbufData(struct HdfSBuf *respData, struct CameraCapability &ability)
{
    bool isFailed = false;

    if (respData == nullptr) {
        CAMERA_LOGE("ReadAbilitySbufData respData param ptr is nullptr, line: %{public}d", __LINE__);
        return RC_ERROR;
    }

    isFailed |= strncpy_s(ability.driver, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= strncpy_s(ability.card, NAME_SIZE, HdfSbufReadString(respData), NAME_SIZE);
    isFailed |= strncpy_s(ability.busInfo, NAME_SIZE, HdfSbufReadString(respData), NAME_SIZE);
    isFailed |= !HdfSbufReadUint32(respData, &ability.capabilities);
    CHECK_RETURN_RESULT(isFailed);

    CAMERA_LOGD("driver: %{public}s, card: %{public}s, busInfo: %{public}s, capabilities: %{public}d\n",
        ability.driver, ability.card, ability.busInfo, ability.capabilities);

    return RC_OK;
}

int CameraControl::ReadSensorSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.sensor.mode);
    isFailed |= strncpy_s(device.sensor.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.sensor.id);
    isFailed |= !HdfSbufReadUint8(respData, &device.sensor.exposure);
    isFailed |= !HdfSbufReadUint8(respData, &device.sensor.mirror);
    isFailed |= !HdfSbufReadUint8(respData, &device.sensor.gain);
    CHECK_RETURN_RESULT(isFailed);

    CAMERA_LOGD("get sensor mode: %{public}d, get sensor driverName: %{public}s, get sensor id: %{public}d, "
        "get sensor exposure: %{public}d, get sensor mirror: %{public}d, get sensor gain: %{public}d\n",
        device.sensor.mode, device.sensor.driverName, device.sensor.id, device.sensor.exposure, device.sensor.mirror,
        device.sensor.gain);

    if (device.sensor.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadIspSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.isp.mode);
    isFailed |= strncpy_s(device.isp.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.id);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.brightness);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.contrast);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.saturation);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.hue);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.sharpness);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.gain);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.gamma);
    isFailed |= !HdfSbufReadUint8(respData, &device.isp.whiteBalance);
    CHECK_RETURN_RESULT(isFailed);

    if (device.isp.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadVcmSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.vcm.mode);
    isFailed |= strncpy_s(device.vcm.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.vcm.id);
    isFailed |= !HdfSbufReadUint8(respData, &device.vcm.focus);
    isFailed |= !HdfSbufReadUint8(respData, &device.vcm.autoFocus);
    isFailed |= !HdfSbufReadUint8(respData, &device.vcm.zoom);
    isFailed |= !HdfSbufReadUint32(respData, &device.vcm.zoomMaxNum);
    CHECK_RETURN_RESULT(isFailed);

    if (device.vcm.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadLensSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.lens.mode);
    isFailed |= strncpy_s(device.lens.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.lens.id);
    isFailed |= !HdfSbufReadUint8(respData, &device.lens.aperture);
    CHECK_RETURN_RESULT(isFailed);

    if (device.lens.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadFlashSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.flash.mode);
    isFailed |= strncpy_s(device.flash.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.flash.id);
    isFailed |= !HdfSbufReadUint8(respData, &device.flash.flashMode);
    isFailed |= !HdfSbufReadUint8(respData, &device.flash.flashIntensity);
    CHECK_RETURN_RESULT(isFailed);

    if (device.flash.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadStreamSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    int32_t i;
    bool isFailed = false;

    isFailed |= !HdfSbufReadUint8(respData, &device.stream.mode);
    isFailed |= strncpy_s(device.stream.driverName, DRIVER_NAME_NUM, HdfSbufReadString(respData), DRIVER_NAME_NUM);
    isFailed |= !HdfSbufReadUint8(respData, &device.stream.id);
    isFailed |= !HdfSbufReadUint32(respData, &device.stream.heightMaxNum);
    isFailed |= !HdfSbufReadUint32(respData, &device.stream.widthMaxNum);
    isFailed |= !HdfSbufReadUint32(respData, &device.stream.frameRateMaxNum);
    isFailed |= !HdfSbufReadUint32(respData, &device.stream.bufferTypeNum);
    isFailed |= !HdfSbufReadUint8(respData, &device.stream.bufferCount);
    for (i = 0; i <= device.stream.bufferTypeNum; i++) {
        isFailed |= !HdfSbufReadUint32(respData, &device.stream.bufferType[i]);
    }
    CHECK_RETURN_RESULT(isFailed);

    if (device.flash.mode == 0) {
        CAMERA_LOGE("device not support sensor\n");
        return RC_ERROR;
    }
    return RC_OK;
}

int CameraControl::ReadDeviceSbufData(int type, struct HdfSBuf *respData, struct DeviceaInfo &device)
{
    int32_t ret;
    if (respData == nullptr) {
        CAMERA_LOGE("param ptr is nullptr, line: %{public}d", __LINE__);
        return RC_ERROR;
    }
    switch (type) {
        case SENSOR_TYPE:
            ret = ReadSensorSbufData(respData, device);
            break;

        case ISP_TYPE:
            ret = ReadIspSbufData(respData, device);
            break;

        case VCM_TYPE:
            ret = ReadVcmSbufData(respData, device);
            break;

        case LENS_TYPE:
            ret = ReadLensSbufData(respData, device);
            break;

        case FLASH_TYPE:
            ret = ReadFlashSbufData(respData, device);
            break;

        case STREAM_TYPE:
            ret = ReadStreamSbufData(respData, device);
            break;

        default:
            CAMERA_LOGE("unknow command\n");
            ret = RC_ERROR;
            break;
    }
    return ret;
}

} // namespace OHOS::Camera
