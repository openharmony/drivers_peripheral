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

#include "sensor_controller.h"
#include <cinttypes>
#include "securec.h"

namespace OHOS::Camera {
std::map<int32_t, uint32_t> SensorController::tagV4L2CidMap_ = {
    {OHOS_SENSOR_EXPOSURE_TIME, V4L2_CID_EXPOSURE_AUTO},
    {OHOS_CONTROL_AWB_MODE, V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE},
    {OHOS_CONTROL_FOCUS_MODE, V4L2_CID_FOCUS_AUTO},
    {OHOS_CONTROL_EXPOSURE_MODE, V4L2_CID_EXPOSURE_AUTO},
    {OHOS_CONTROL_FLASH_MODE, V4L2_CID_FLASH_LED_MODE},
};
std::map<int32_t, TagFunType> SensorController::tagMethodMap_ = {
    {OHOS_SENSOR_EXPOSURE_TIME, SensorController::GetExposureTime},
    {OHOS_CONTROL_FOCUS_MODE, SensorController::GetFocusMode},
    {OHOS_CONTROL_EXPOSURE_MODE, SensorController::GetExposureMode},
    {OHOS_CONTROL_FLASH_MODE, SensorController::GetFlashMode},
};
SensorController::SensorController() {}

SensorController::SensorController(std::string hardwareName) : IController(hardwareName), buffCont_(0) {}

SensorController::~SensorController() {}

RetCode SensorController::Init()
{
    sensorVideo_ = std::make_shared<HosV4L2Dev>();
    if (sensorVideo_ == nullptr) {
        CAMERA_LOGE("%s Create HosV4L2Dev fail", __FUNCTION__);
        return RC_ERROR;
    }

    // push default value
    constexpr uint32_t FPS_FIVE = 5;
    constexpr uint32_t FPS_TEN = 10;
    fpsRange_.push_back(FPS_FIVE);
    fpsRange_.push_back(FPS_TEN);
    return RC_OK;
}

RetCode SensorController::PowerUp()
{
    RetCode rc = RC_OK;
    if (GetPowerOnState() == false) {
        SetPowerOnState(true);
        CAMERA_LOGI("%s Sensor Powerup", __FUNCTION__);
        return rc;
    }
    return rc;
}

RetCode SensorController::PowerDown()
{
    RetCode rc = RC_OK;
    if (GetPowerOnState() == true) {
        SetPowerOnState(false);
        sensorVideo_->StopStream(GetName());
        sensorVideo_->ReleaseBuffers(GetName());
        sensorVideo_->stop(GetName());
        CAMERA_LOGI("%s Sensor PowerDown", __FUNCTION__);
        return rc;
    }
    return rc;
}

RetCode SensorController::Configure(std::shared_ptr<CameraMetadata> meta)
{
    return SendSensorMetaData(meta);
};

RetCode SensorController::ConfigFps(std::shared_ptr<CameraMetadata> meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("Meta is nullptr");
        return RC_ERROR;
    }
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("Data is nullptr");
        return RC_ERROR;
    }
    RetCode rc = SendFpsMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendFpsMetaData fail");
    }
    return rc;
}

RetCode SensorController::ConfigStart()
{
    CAMERA_LOGI("%s ConfigStart", __FUNCTION__);
    std::lock_guard<std::mutex> lock(startSensorLock_);
    RetCode rc = RC_OK;
    if (startSensorState_ == false) {
        configState_ = true;
        rc = sensorVideo_->start(GetName());
        if (rc == RC_ERROR) {
            CAMERA_LOGE("ConfigStart fail");
            return rc;
        }
    }
    return rc;
}

RetCode SensorController::ConfigStop()
{
    CAMERA_LOGI("%s ConfigStop", __FUNCTION__);
    std::lock_guard<std::mutex> lock(startSensorLock_);
    RetCode rc = RC_OK;
    if (startSensorState_ == false && configState_ == true) {
        rc = sensorVideo_->stop(GetName());
        configState_ = false;
    }
    return rc;
}

RetCode SensorController::Start(int buffCont, DeviceFormat& format)
{
    CAMERA_LOGI("%s Start", __FUNCTION__);
    std::lock_guard<std::mutex> lock(startSensorLock_);
    RetCode rc = RC_OK;
    if (startSensorState_ == false) {
        buffCont_ = buffCont;
        startSensorState_ = true;
        sensorVideo_->start(GetName());
        sensorVideo_->ConfigSys(GetName(), CMD_V4L2_SET_FORMAT, format);
        sensorVideo_->ReqBuffers(GetName(), buffCont_);
    }
    return rc;
};

RetCode SensorController::Stop()
{
    CAMERA_LOGI("%s Stop", __FUNCTION__);
    std::lock_guard<std::mutex> lock(startSensorLock_);
    RetCode rc = RC_OK;
    if (startSensorState_ == true) {
        sensorVideo_->StopStream(GetName());
        sensorVideo_->ReleaseBuffers(GetName());
        sensorVideo_->stop(GetName());
        startSensorState_ = false;
        configState_ = false;
    }
    return rc;
};

RetCode SensorController::SendFrameBuffer(std::shared_ptr<FrameSpec> buffer)
{
    RetCode ret = RC_OK;
    if (buffCont_ >= 1) {
        CAMERA_LOGI("buffCont_ %{public}d", buffCont_);
        sensorVideo_->CreatBuffer(GetName(), buffer);
        if (buffCont_ == 1) {
            ret = sensorVideo_->StartStream(GetName());
        }
        buffCont_--;
    } else {
        ret = sensorVideo_->QueueBuffer(GetName(), buffer);
    }
    return ret;
}

void SensorController::SetNodeCallBack(const NodeBufferCb cb)
{
    CAMERA_LOGI("SensorController SetNodeCallBack entry");
    nodeBufferCb_ = cb;
    sensorVideo_->SetV4L2DevCallback([&](std::shared_ptr<FrameSpec> buffer) {
        BufferCallback(buffer);
    });
}

void SensorController::BufferCallback(std::shared_ptr<FrameSpec> buffer)
{
    if (nodeBufferCb_ == nullptr) {
        CAMERA_LOGE("nodeBufferCb_ is nullptr");
        return;
    }

    constexpr int64_t UNIT_COUNT = 1000;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t timestamp = tv.tv_sec * UNIT_COUNT * UNIT_COUNT * UNIT_COUNT + tv.tv_usec * UNIT_COUNT;
    buffer->buffer_->SetEsTimestamp(timestamp);
    nodeBufferCb_(buffer);
}

RetCode SensorController::GetAbilityMetaData(std::shared_ptr<CameraMetadata> meta)
{
    return GetSensorMetaData(meta);
}

void SensorController::SetAbilityMetaDataTag(std::vector<int32_t> abilityMetaDataTag)
{
    std::lock_guard<std::mutex> lock(metaDataSetlock_);
    std::vector<int32_t>().swap(abilityMetaData_);
    for (auto it = abilityMetaDataTag.cbegin(); it != abilityMetaDataTag.cend(); it++) {
        switch (*it) {
            case OHOS_SENSOR_COLOR_CORRECTION_GAINS: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_SENSOR_EXPOSURE_TIME: {
                abilityMetaData_.push_back(*it);
                break;
            }
            case OHOS_CONTROL_EXPOSURE_MODE: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_CONTROL_AE_EXPOSURE_COMPENSATION: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_CONTROL_FOCUS_MODE: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_CONTROL_METER_MODE: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_CONTROL_FLASH_MODE: {
                abilityMetaData_.push_back((*it));
                break;
            }
            case OHOS_CONTROL_FPS_RANGES: {
                abilityMetaData_.push_back((*it));
                break;
            }
            default:
                break;
        }
    }
}

RetCode SensorController::GetSensorMetaData(std::shared_ptr<CameraMetadata> meta)
{
    RetCode rc = RC_OK;
    int32_t outValue = 0;

    std::lock_guard<std::mutex> lock(metaDataSetlock_);
    for (auto &keyTag : abilityMetaData_) {
        auto hasCmdMem = tagV4L2CidMap_.find(keyTag);
        if (hasCmdMem == tagV4L2CidMap_.end()) {
            continue;
        }

        rc = sensorVideo_->QuerySetting(GetName(), tagV4L2CidMap_[keyTag], &outValue);
        if (rc == RC_ERROR) {
            continue;
        }

        auto hasFuncMem = tagMethodMap_.find(keyTag);
        if (hasFuncMem == tagMethodMap_.end()) {
            continue;
        }
        tagMethodMap_[keyTag](this, meta, outValue);
    }

    // dummy value start
    outValue = 1;
    GetExposureCompensation(this, meta, outValue);
    outValue = 0;
    GetFocusMode(this, meta, outValue);
    outValue = 1;
    GetMeterMode(this, meta, outValue);
    GetFpsRange(this, meta);
    outValue = 1;
    GetFlashMode(this, meta, outValue);
    rc = RC_OK;
    // dummy value end

    return rc;
}

RetCode SensorController::GetAEMetaData(std::shared_ptr<CameraMetadata> meta)
{
    static int64_t oldExpoTime = 0;
    int64_t expoTime = 0;
    RetCode rc = RC_ERROR;
    std::lock_guard<std::mutex> metaDataLock(metaDataSetlock_);
    for (auto iter = abilityMetaData_.cbegin(); iter != abilityMetaData_.cend(); iter++) {
        if (*iter == OHOS_SENSOR_EXPOSURE_TIME) {
            rc = sensorVideo_->QuerySetting(GetName(), CMD_AE_EXPO, (int*)&expoTime);
            CAMERA_LOGD("%s Get CMD_AE_EXPOTIME [%" PRId64 "]", __FUNCTION__, expoTime);
            if (rc == RC_ERROR) {
                CAMERA_LOGE("%s CMD_AE_EXPO QuerySetting fail", __FUNCTION__);
                return rc;
            }
            if (oldExpoTime != expoTime) {
                std::lock_guard<std::mutex> flagLock(metaDataFlaglock_);
                metaDataFlag_ = true;
                oldExpoTime = expoTime;
            }
            meta->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
        }
    }
    return rc;
}

RetCode SensorController::GetAWBMetaData(std::shared_ptr<CameraMetadata> meta)
{
    static float oldColorGains[4] = {0};
    float colorGains[4] = {0};
    int value = 0;
    RetCode rc = RC_ERROR;
    std::lock_guard<std::mutex> metaDataLock(metaDataSetlock_);
    for (auto iter = abilityMetaData_.cbegin(); iter != abilityMetaData_.cend(); iter++) {
        if (*iter != OHOS_SENSOR_COLOR_CORRECTION_GAINS) {
            continue;
        }
        rc = sensorVideo_->QuerySetting(GetName(), CMD_AWB_COLORGAINS, &value);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("%s CMD_AWB_COLORGAINS QuerySetting fail", __FUNCTION__);
            return rc;
        }
        colorGains[0] = (float)value;
        int gainsSize = 4;
        if (!CheckNumequal(oldColorGains, colorGains, gainsSize)) {
            std::lock_guard<std::mutex> flagLock(metaDataFlaglock_);
            metaDataFlag_ = true;
            errno_t ret = memcpy_s(oldColorGains, sizeof(oldColorGains) / sizeof(float), colorGains,
                gainsSize * sizeof(float));
            if (ret != EOK) {
                CAMERA_LOGE("memcpy_s failed, ret = %{public}d", ret);
                return RC_ERROR;
            }
        }
        meta->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4); // 4:data size
    }
    return rc;
}

void SensorController::GetFocusMode(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t focusMode = value;

    CAMERA_LOGI("Get CMD_FOCUS_MODE [%{public}]", focusMode);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, 1);
}

void SensorController::GetFocusState(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta,
    const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t focusState = value;

    CAMERA_LOGI("Get CMD_FOCUS_SATE [%{public}]", focusState);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_FOCUS_STATE, &focusState, 1);
}

void SensorController::GetExposureMode(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t exposureMode = value;

    CAMERA_LOGI("Get CMD_FEXPOSURE_MODE [%{public}]", exposureMode);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &exposureMode, 1);
}

void SensorController::GetExposureTime(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    int64_t exposureTime = value;

    CAMERA_LOGI("Get CMD_FEXPOSURE_TIME [%{public}]", exposureTime);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, 1);
}

void SensorController::GetExposureCompensation(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    int32_t exposureCompensation = value;
    constexpr uint32_t DATA_COUNT = 1;
    CAMERA_LOGI("Get CMD_FEXPOSURE_COMPENSATION [%{public}]", exposureCompensation);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, DATA_COUNT);

    // dummy data
    uint8_t videoStabiliMode = OHOS_CAMERA_VIDEO_STABILIZATION_OFF;
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, DATA_COUNT);
}

void SensorController::GetMeterMode(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t meterMode = value;

    CAMERA_LOGI("Get CMD_METER_MODE [%{public}]", meterMode);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_METER_MODE, &meterMode, 1);
}

void SensorController::GetExposureState(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t exposureState = value;

    CAMERA_LOGI("Get CMD_EXPOSURE_STATE [%{public}]", exposureState);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_EXPOSURE_STATE, &exposureState, 1);
}

void SensorController::GetFlashMode(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t flashMode = value;

    CAMERA_LOGI("Get CMD_FLASH_MODE [%{public}]", flashMode);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, 1);
}

void SensorController::GetCaptureMirror(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta, const int32_t &value)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    uint8_t captureMirror = value;

    CAMERA_LOGI("Get CMD_CAPTURE_MIRROR [%{public}]", captureMirror);
    std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
    sensorController->metaDataFlag_ = true;
    meta->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &captureMirror, 1);
}

void SensorController::GetFpsRange(SensorController *sensorController,
    std::shared_ptr<CameraMetadata> meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }

    for (auto iter = abilityMetaData_.cbegin(); iter != abilityMetaData_.cend(); iter++) {
        if (*iter == OHOS_CONTROL_FPS_RANGES) {
            DeviceFormat format;
            std::lock_guard<std::mutex> lock(sensorController->metaDataFlaglock_);
            sensorController->metaDataFlag_ = true;
            RetCode rc = sensorVideo_->ConfigSys(GetName(), CMD_V4L2_GET_FPS, format);
            if (rc == RC_ERROR) {
                CAMERA_LOGE("CMD_V4L2_GET_FPS ConfigSys fail");
            }

            // dummy data
            meta->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange_.data(), fpsRange_.size());
        }
    }
}

RetCode SensorController::SendSensorMetaData(std::shared_ptr<CameraMetadata> meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return RC_ERROR;
    }
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return RC_ERROR;
    }
    RetCode rc = SendAWBMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendAWBMetaData fail");
    }
    rc = SendAWBLockMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendAWBLockMetaData fail");
    }
    rc = SendExposureMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendExposureMetaData fail");
    }
    rc = SendAELockMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendAELockMetaData fail");
    }
    rc = SendFocusMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendFocusMetaData fail");
    }
    rc = SendFocusRegionsMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendFocusRegionsMetaData fail");
    }
    rc = SendMeterMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendMeterMetaData fail");
    }
    rc = SendFlashMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendFlashMetaData fail");
    }
    return rc;
}

RetCode SensorController::SendAEMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &entry);
    if (ret == 0) {
        int32_t expo = *(entry.data.i32);
        if (expo != 0) {
            int32_t aemode = 1;
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_AE_EXPO, (int*)&aemode);
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_AE_EXPOTIME, (int*)&expo);
            CAMERA_LOGI("%s Set CMD_AE_EXPO EXPOTIME[%d] EXPO[%d]", __FUNCTION__, expo, aemode);
        } else {
            int32_t aemode = 0;
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_AE_EXPO, (int*)&aemode);
            CAMERA_LOGI("%s Set CMD_AE_EXPOTIME [%d]", __FUNCTION__, aemode);
        }
        if (rc == RC_ERROR) {
            CAMERA_LOGE("%s Send CMD_AE_EXPOTIME fail", __FUNCTION__);
            return rc;
        }
    }
    return rc;
}

RetCode SensorController::SendAWBMetaData(common_metadata_header_t *data)
{
    uint8_t awbMode = 0;
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AWB_MODE, &entry);
    if (ret == 0) {
        awbMode = *(entry.data.u8);
        int awbModeVal = V4L2_WHITE_BALANCE_AUTO;
        // Can not find tag for OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT and OHOS_CAMERA_AWB_MODE_TWILIGHT
        // in V4L2, so set V4L2_WHITE_BALANCE_AUTO.
        if (awbMode == OHOS_CAMERA_AWB_MODE_AUTO ||
            awbMode == OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT ||
            awbMode == OHOS_CAMERA_AWB_MODE_TWILIGHT) {
            awbModeVal = V4L2_WHITE_BALANCE_AUTO;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_OFF) {
            awbModeVal = V4L2_WHITE_BALANCE_MANUAL;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_INCANDESCENT) {
            awbModeVal = V4L2_WHITE_BALANCE_INCANDESCENT;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_FLUORESCENT) {
            awbModeVal = V4L2_WHITE_BALANCE_FLUORESCENT;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_DAYLIGHT) {
            awbModeVal = V4L2_WHITE_BALANCE_DAYLIGHT;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT) {
            awbModeVal = V4L2_WHITE_BALANCE_CLOUDY;
        }

        if (awbMode == OHOS_CAMERA_AWB_MODE_SHADE) {
            awbModeVal = V4L2_WHITE_BALANCE_SHADE;
        }

        rc = sensorVideo_->UpdateSetting(GetName(), CMD_AWB_MODE, &awbModeVal);
        CAMERA_LOGI("Set CMD_AWB_MODE [%{public}d]", awbMode);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_AWB_MODE value=%{public}d success", awbModeVal);
        } else {
            CAMERA_LOGE("Send OHOS_CONTROL_AWB_MODE value=%{public}d failed", awbModeVal);
        }
    }
    return rc;
}

RetCode SensorController::SendAWBLockMetaData(common_metadata_header_t *data)
{
    uint8_t awbLock = 0;
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AWB_LOCK, &entry);
    if (ret == 0) {
        awbLock = *(entry.data.u8);
        uint32_t curLock = 0;
        sensorVideo_->QuerySetting(GetName(), V4L2_CID_3A_LOCK, reinterpret_cast<int*>(&curLock));
        if (awbLock == OHOS_CAMERA_AWB_LOCK_ON) {
        // set the position of AWB bit to 1;
            curLock |= V4L2_LOCK_WHITE_BALANCE;
        } else if (awbLock == OHOS_CAMERA_AWB_LOCK_OFF) {
            // set the position of AWB bit to 0;
            curLock &= ~V4L2_LOCK_WHITE_BALANCE;
        }
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_AWB_LOCK, reinterpret_cast<int*>(&curLock));
        CAMERA_LOGI("Set CMD_AWB_LOCK [%{public}d]", awbLock);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_AWB_LOCK value=%{public}d success", curLock);
        } else {
            CAMERA_LOGE("Send OHOS_CONTROL_AWB_LOCK value=%{public}d failed", curLock);
        }
    }
    return rc;
}

RetCode SensorController::SendExposureMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;

    SendExposureModeMetaData(data);

    int64_t exposureTime = 0;
    int ret = FindCameraMetadataItem(data, OHOS_SENSOR_EXPOSURE_TIME, &entry);
    if (ret == 0) {
        exposureTime = *(entry.data.i64);
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_AE_EXPOTIME, (int*)&exposureTime);
        CAMERA_LOGI("Set CMD_AE_EXPOTIME [%{public}d]", exposureTime);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_SENSOR_EXPOSURE_TIME value=%{public}d success", exposureTime);
        } else {
            CAMERA_LOGE("Send OHOS_SENSOR_EXPOSURE_TIME value=%{public}d failed", exposureTime);
        }
    }

    int32_t exposureCompensation = 0;
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &entry);
    if (ret == 0) {
        exposureCompensation = *(entry.data.i32);
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_COMPENSATION,
                                         (int*)&exposureCompensation);
        CAMERA_LOGI("Set CMD_EXPOSURE_COMPENSATION [%{public}d]", exposureCompensation);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_EXPOSURE_COMPENSATION fail");
        }
    }

    return rc;
}

void SensorController::CheckRetCodeValue(RetCode rc)
{
    if (rc == RC_ERROR) {
        CAMERA_LOGE("Send CMD_EXPOSURE_LOCK fail");
    }
}

void SensorController::CheckUpdateSettingRetCode(RetCode rc, int exposureVal)
{
    if (rc == RC_OK) {
        CAMERA_LOGI("Send OHOS_CONTROL_EXPOSURE_MODE value=%{public}d success", exposureVal);
    } else {
        CAMERA_LOGE("Send OHOS_CONTROL_EXPOSURE_MODE value=%{public}d failed", exposureVal);
    }
}

RetCode SensorController::SendExposureModeMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
    if (ret == 0) {
        uint8_t aeLock = 0;
        bool isAutoMode = false;
        uint8_t exposureMode = *(entry.data.u8);
        int exposureVal = V4L2_EXPOSURE_AUTO;
        if (exposureMode == OHOS_CAMERA_EXPOSURE_MODE_MANUAL) {
            exposureVal = V4L2_EXPOSURE_MANUAL;
        } else if (exposureMode == OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO) {
            exposureVal = V4L2_EXPOSURE_AUTO;
            isAutoMode = true;
        } else if (exposureMode == OHOS_CAMERA_EXPOSURE_MODE_AUTO) {
            exposureVal = V4L2_EXPOSURE_AUTO;
            isAutoMode = true;
        }
        int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_LOCK, &entry);
        if (ret == 0) {
            aeLock = *(entry.data.u8);
        }
        if (aeLock == 0) {
            unsigned int curLock = 0;
            auto queryResult = sensorVideo_->QuerySetting(GetName(), V4L2_CID_3A_LOCK,
                reinterpret_cast(&curLock));
            curLock = exposureMode == OHOS_CAMERA_EXPOSURE_MODE_LOCKED ?
                curLock | V4L2_LOCK_EXPOSURE : curLock & ~V4L2_LOCK_EXPOSURE;
            if (queryResult == RC_OK) {
                rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_LOCK, reinterpret_cast(&curLock));
                CAMERA_LOGI("Set CMD_EXPOSURE_LOCK [%{public}d]", exposureMode);
                CheckRetCodeValue(rc);
            }
            if (isAutoMode == true) {
                rc = SendExposureAutoModeMetaData(data);
            } else {
                rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_MODE, (int*)&exposureVal);
                CAMERA_LOGI("Set CMD_EXPOSURE_MODE [%{public}d]", exposureMode);
                CheckUpdateSettingRetCode(rc, exposureVal);
            }
        }
    }
    return rc;
}

RetCode SensorController::SendExposureAutoModeMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    uint8_t exposureMode = 0;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
    if (ret == 0) {
        exposureMode = *(entry.data.u8);
        int exposureVal = V4L2_EXPOSURE_AUTO;

        if (exposureMode == OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO ||
            exposureMode == OHOS_CAMERA_EXPOSURE_MODE_AUTO) {
            exposureVal = V4L2_EXPOSURE_AUTO;
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_MODE, (int*)&exposureVal);
        }
        if (rc == RC_ERROR) {
            exposureVal = V4L2_EXPOSURE_SHUTTER_PRIORITY;
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_MODE, (int*)&exposureVal);
        }
        if (rc == RC_ERROR) {
            exposureVal = V4L2_EXPOSURE_APERTURE_PRIORITY;
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_EXPOSURE_MODE, (int*)&exposureVal);
        }
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_EXPOSURE_MODE value=%{public}d success", exposureVal);
        } else {
            CAMERA_LOGE("Send OHOS_CONTROL_EXPOSURE_MODE value=%{public}d failed", exposureVal);
        }
    }
    return rc;
}

RetCode SensorController::SendAELockMetaData(common_metadata_header_t *data)
{
    uint8_t aeLock = 0;
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_LOCK, &entry);
    if (ret == 0) {
        aeLock = *(entry.data.u8);
        unsigned int curLock = 0;
        sensorVideo_->QuerySetting(GetName(), V4L2_CID_3A_LOCK, reinterpret_cast<int*>(&curLock));
        if (aeLock == OHOS_CAMERA_AE_LOCK_ON) {
            // set the position of AE bit to 1;
            curLock |= V4L2_LOCK_EXPOSURE;
        } else if (aeLock == OHOS_CAMERA_AE_LOCK_OFF) {
            // set the position of AE bit to 0;
            curLock &= ~V4L2_LOCK_EXPOSURE;
        }

        rc = sensorVideo_->UpdateSetting(GetName(), CMD_AE_LOCK, reinterpret_cast<const int*>(&curLock));
        CAMERA_LOGI("Set CMD_AE_LOCK [%{public}d]", aeLock);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_AE_LOCK value=%{public}d success", curLock);
        } else {
            CAMERA_LOGE("Send OHOS_CONTROL_AE_LOCK value=%{public}d failed", curLock);
        }
    }
    return rc;
}

RetCode SensorController::SendFocusMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    uint8_t focusMode = 0;
    AdapterCmd focusModeCmd = CMD_AUTO_FOCUS_START;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_MODE, &entry);
    if (ret == 0) {
        focusMode = *(entry.data.u8);
        uint32_t curLock = 0;
        auto queryResult = sensorVideo_->QuerySetting(GetName(), V4L2_CID_3A_LOCK, reinterpret_cast<int*>(&curLock));
        if (focusMode == OHOS_CAMERA_FOCUS_MODE_LOCKED) {
            curLock |= V4L2_LOCK_FOCUS;
        } else {
            curLock &= ~V4L2_LOCK_FOCUS;
        }

        if (queryResult == RC_OK) {
            rc = sensorVideo_->UpdateSetting(GetName(), CMD_FOCUS_LOCK, reinterpret_cast<const int*>(&curLock));
            CAMERA_LOGI("Set CMD_FOCUS_LOCK [%{public}d]", focusMode);
            if (rc == RC_OK) {
                CAMERA_LOGI("Send OHOS_CONTROL_FOCUS_MODE value=%{public}d success", focusMode);
            } else {
                CAMERA_LOGE("Send OHOS_CONTROL_FOCUS_MODE value=%{public}d failed", focusMode);
            }
        }

        int focusVal = 0;
        if (focusMode == OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO) {
            focusVal = 1;
        } else if (focusMode == OHOS_CAMERA_FOCUS_MODE_MANUAL) {
            focusVal = 0;
            focusModeCmd = CMD_AUTO_FOCUS_STOP;
        } else if (focusMode == OHOS_CAMERA_FOCUS_MODE_AUTO) {
            focusVal = 0;
            focusModeCmd = CMD_AUTO_FOCUS_START;
        }

        rc = sensorVideo_->UpdateSetting(GetName(), CMD_FOCUS_AUTO, &focusVal);
        CAMERA_LOGI("Set CMD_FOCUS_AUTO [%{public}d]", focusMode);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_FOCUS_MODE value=[%{public}d] success", focusMode);
        } else {
            CAMERA_LOGI("Send OHOS_CONTROL_FOCUS_MODE value=[%{public}d] failed", focusMode);
        }

        focusVal = 1;
        rc = sensorVideo_->UpdateSetting(GetName(), focusModeCmd, &focusVal);
        CAMERA_LOGI("Set CMD_FOCUS_AUTO [%{public}d]", focusMode);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_FOCUS_AUTO fail");
        }
    }
    return rc;
}

RetCode SensorController::SendFocusRegionsMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    std::vector<int32_t> afRegions;
    const uint32_t GROUP_LEN = 2;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AF_REGIONS, &entry);
    if (ret == 0) {
        for (uint32_t i = 0; i < entry.count; i++) {
            afRegions.push_back(*(entry.data.i32 + i));
            CAMERA_LOGI("Set afRegions [%{public}d]", *(entry.data.i32 + i));
        }
        if (afRegions.size() != GROUP_LEN) {
            CAMERA_LOGE("afRegions size error");
            return RC_ERROR;
        }

        int32_t averageVal = (afRegions[0] + afRegions[1]) / GROUP_LEN;
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_FOCUS_ABSOLUTE, (int*)&averageVal);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_FOCUS_ABSOLUTE fail");
        }
    }

    return rc;
}

RetCode SensorController::SendMeterMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    uint8_t meterMode = 0;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_METER_MODE, &entry);
    if (ret == 0) {
        meterMode = *(entry.data.u8);
        int meterModeVal = 0;
        if (meterMode == OHOS_CAMERA_SPOT_METERING) {
            meterModeVal = V4L2_EXPOSURE_METERING_SPOT;
        }
        if (meterMode == OHOS_CAMERA_REGION_METERING) {
            meterModeVal = V4L2_EXPOSURE_METERING_MATRIX;
        }
        if (meterMode == OHOS_CAMERA_OVERALL_METERING) {
            meterModeVal = V4L2_EXPOSURE_METERING_AVERAGE;
        }
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_METER_MODE, &meterModeVal);
        CAMERA_LOGI("Set CMD_METER_MODE [%{public}d]", meterMode);
        if (rc == RC_OK) {
            CAMERA_LOGI("Send OHOS_CONTROL_METER_MODE value=%{public}d success", meterModeVal);
        } else {
            CAMERA_LOGE("Send OHOS_CONTROL_METER_MODE value=%{public}d failed", meterModeVal);
        }
    }

    std::vector<int32_t> meterPoint;
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_METER_POINT, &entry);
    if (ret == 0) {
        for (uint32_t i = 0; i < entry.count; i++) {
            meterPoint.push_back(*(entry.data.i32 + i));
            CAMERA_LOGI("Set CMD_METER_POINT [%{public}d]", *(entry.data.i32 + i));
        }
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_METER_POINT, (int*)&meterPoint);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_METER_POINT fail");
        }
    }

    return rc;
}

RetCode SensorController::SendFlashMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FLASH_MODE, &entry);
    if (ret == 0) {
        uint8_t flashMode = *(entry.data.u8);
        rc = sensorVideo_->UpdateSetting(GetName(), CMD_FLASH_MODE, (int*)&flashMode);
        CAMERA_LOGI("Set CMD_FLASH_MODE [%{public}d]", flashMode);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_FLASH_MODE fail");
        }
    }

    return rc;
}

RetCode SensorController::SendFpsMetaData(common_metadata_header_t *data)
{
    RetCode rc = RC_OK;
    camera_metadata_item_t entry;
    constexpr uint32_t GROUP_LEN = 2;
    DeviceFormat format;
    fpsRange_.clear();
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FPS_RANGES, &entry);
    if (ret == 0) {
        for (uint32_t i = 0; i < entry.count; i++) {
            fpsRange_.push_back(*(entry.data.i32 + i));
        }
        if (fpsRange_.size() != GROUP_LEN) {
            CAMERA_LOGE("fpsRange size error");
            return RC_ERROR;
        }
        CAMERA_LOGI("Set CMD_FPS_RANGE [%{public}d, %{public}d]", fpsRange_[0], fpsRange_[1]);
        format.fmtdesc.fps.denominator = (fpsRange_[0] + fpsRange_[1]) / GROUP_LEN;
        format.fmtdesc.fps.numerator = 1;
        CAMERA_LOGI("fps.denominator: %{public}d, fps.numerator: %{public}d",
            format.fmtdesc.fps.denominator, format.fmtdesc.fps.numerator);
        rc = sensorVideo_->ConfigSys(GetName(), CMD_V4L2_SET_FPS, format);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Send CMD_FPS_RANGE fail");
        }
    }

    return rc;
}

RetCode SensorController::Flush(int32_t streamId)
{
    CAMERA_LOGD("SensorController::Flush streamId = %{public}d", streamId);
    return sensorVideo_->Flush(GetName());
}

void SensorController::SetMemoryType(uint8_t &memType)
{
    sensorVideo_->SetMemoryType(memType);
    return;
}
} // namespace OHOS::Camera
