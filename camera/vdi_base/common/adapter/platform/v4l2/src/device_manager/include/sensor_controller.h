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

#ifndef HOS_CAMERA_SENSOR_CONTROLLER_H
#define HOS_CAMERA_SENSOR_CONTROLLER_H

#include "icontroller.h"
#include "device_manager_adapter.h"
#include "v4l2_dev.h"
#include "v4l2_common.h"

namespace OHOS::Camera {
class SensorController;
using TagFunType = std::function<void(SensorController*, std::shared_ptr<CameraMetadata>, const int32_t&)>;
class SensorController : public IController {
public:
    SensorController();
    explicit SensorController(std::string hardwareName);
    virtual ~SensorController();
    RetCode Init();
    RetCode PowerUp();
    RetCode PowerDown();
    RetCode Configure(std::shared_ptr<CameraMetadata> meta);
    RetCode ConfigFps(std::shared_ptr<CameraMetadata> meta);
    RetCode ConfigStart();
    RetCode ConfigStop();
    RetCode Start(int buffCont, DeviceFormat& format);
    RetCode Stop();

    RetCode SendFrameBuffer(std::shared_ptr<FrameSpec> buffer);

    void SetNodeCallBack(const NodeBufferCb cb);
    void BufferCallback(std::shared_ptr<FrameSpec> buffer);

    void SetAbilityMetaDataTag(std::vector<int32_t> abilityMetaDataTag);
    RetCode GetAbilityMetaData(std::shared_ptr<CameraMetadata> meta);
    RetCode Flush(int32_t streamId);
    void SetMemoryType(uint8_t &memType);

private:
    RetCode SendSensorMetaData(std::shared_ptr<CameraMetadata> meta);
    RetCode SendAEMetaData(common_metadata_header_t *data);
    RetCode SendAELockMetaData(common_metadata_header_t *data);
    RetCode SendAWBMetaData(common_metadata_header_t *data);
    RetCode SendAWBLockMetaData(common_metadata_header_t *data);
    RetCode SendExposureMetaData(common_metadata_header_t *data);
    void CheckRetCodeValue(RetCode rc);
    void CheckUpdateSettingRetCode(RetCode rc, int exposureVal);
    RetCode SendExposureModeMetaData(common_metadata_header_t *data);
    RetCode SendExposureAutoModeMetaData(common_metadata_header_t *data);
    RetCode SendFocusMetaData(common_metadata_header_t *data);
    RetCode SendFocusRegionsMetaData(common_metadata_header_t *data);
    RetCode SendMeterMetaData(common_metadata_header_t *data);
    RetCode SendFlashMetaData(common_metadata_header_t *data);
    RetCode SendFpsMetaData(common_metadata_header_t *data);
    RetCode SetFocusRegions(common_metadata_header_t *data);
    RetCode GetSensorMetaData(std::shared_ptr<CameraMetadata> meta);
    RetCode GetAEMetaData(std::shared_ptr<CameraMetadata> meta);
    RetCode GetAWBMetaData(std::shared_ptr<CameraMetadata> meta);
    static void GetFocusMode(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetFocusState(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetExposureMode(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetExposureTime(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetExposureCompensation(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetMeterMode(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetExposureState(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetFlashMode(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetCaptureMirror(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetBasicConfigurations(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    void GetFpsRange(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta);
    static void GetJpegOrientation(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);
    static void GetJpegQuality(SensorController *sensorController,
        std::shared_ptr<CameraMetadata> meta, const int32_t &value);

    template<typename T>
    bool CheckNumequal(T oldnum, T num, int size)
    {
        if (oldnum == nullptr || num == nullptr) {
            CAMERA_LOGE("oldnum or num is nullptr");
            return false;
        }
        for (int i = 0; size > 0; i++, size--) {
            if (oldnum[i] != num[i]) {
                return false;
            }
        }
        return true;
    };
    std::mutex startSensorLock_;
    bool startSensorState_ = false;
    NodeBufferCb nodeBufferCb_ = nullptr;
    std::vector<int32_t> abilityMetaData_;
    std::mutex metaDataSetlock_;
    std::mutex metaDataFlaglock_;
    bool metaDataFlag_ = false;
    int buffCont_ = 0;
    std::shared_ptr<HosV4L2Dev> sensorVideo_;
    static std::map<int32_t, uint32_t> tagV4L2CidMap_;
    static std::map<int32_t, TagFunType> tagMethodMap_;
    std::vector<int32_t> fpsRange_;
    bool configState_ = false;
    bool is3aAeLock_ = false;
};
} // namespace OHOS::Camera
#endif
