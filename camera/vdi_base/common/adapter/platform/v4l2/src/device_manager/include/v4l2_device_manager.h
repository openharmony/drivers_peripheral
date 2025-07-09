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

#ifndef HOS_CAMERA_V4L2_DEVICE_MANAGER_H
#define HOS_CAMERA_V4L2_DEVICE_MANAGER_H

#include <iostream>
#include <vector>
#include <set>
#include <algorithm>
#include <mutex>
#include "create_devicemanager_factory.h"
#include "icontroller.h"
#include "idevice_manager.h"
#include "enumerator_manager.h"
#include "imanager.h"
#include "v4l2_dev.h"
#include "device_manager_adapter.h"

namespace OHOS::Camera {
class V4L2DeviceManager : public IDeviceManager {
    DECLARE_DEVICEMANAGER(V4L2DeviceManager)
public:
    V4L2DeviceManager();
    virtual ~V4L2DeviceManager();
    std::shared_ptr<IManager> GetManager(ManagerId managerId);
    std::shared_ptr<ISensor> GetSensor(CameraId cameraId);
    RetCode DestroyManager();
    RetCode Init();
    std::shared_ptr<IController> GetController(CameraId cameraId, ManagerId managerId, ControllerId controllerId);
    RetCode PowerUp(CameraId cameraId);
    RetCode PowerDown(CameraId cameraId);
    std::vector<CameraId> GetCameraId();
    RetCode SetFlashlight(FlashMode flashMode, bool enable, CameraId cameraId = CAMERA_MAX);
    void Configure(std::shared_ptr<CameraMetadata> meta);
    void SetMetaDataCallBack(const MetaDataCb cb, CameraId cameraId = CAMERA_MAX);
    void SetHotplugDevCallBack(HotplugDevCb cb);
    void SetAbilityMetaDataTag(std::vector<int32_t> abilityMetaDataTag);
    void SetMemoryType(uint8_t &memType);
    CameraId HardwareToCameraId(std::string hardwareName) override;

private:
    void AddHardware(CameraId id, const std::string hardwareName);
    void UvcCallBack(const std::string hardwareName, std::vector<DeviceControl>& deviceControl,
        std::vector<DeviceFormat>& deviceFormat, bool uvcState);
    void UvcinfoToMetaData();
    RetCode CreateController(CameraId cameraId, std::shared_ptr<IManager> manager, ManagerId managerId);
    RetCode DestroyController();
    bool CheckManagerList(ManagerId managerId);
    bool CheckCameraIdList(CameraId cameraId);
    RetCode CreateManager();
    std::string CameraIdToHardware(CameraId cameraId, ManagerId managerId);
    CameraId ReturnEnableCameraId(std::string hardwareName);
    void Convert(std::vector<DeviceControl>& deviceControlVec, std::vector<DeviceFormat>& deviceFmat,
                 std::shared_ptr<CameraMetadata> cameraMeta);
    int GetOhosMetaTag(uint32_t v4l2Tag);
    void ConvertV4l2TagToOhos(std::vector<DeviceControl>& deviceControlVec, std::vector<DeviceFormat>& deviceFormat,
                              std::shared_ptr<CameraMetadata> cameraMetadata);
    void AddDefaultOhosTag(std::shared_ptr<CameraMetadata> cameraMetadata, std::vector<DeviceFormat>& deviceFormat);
    RetCode ConvertEntryToOhos(std::shared_ptr<CameraMetadata> metadata, int ohosTag,
                               const DeviceControl& deviceControl);

    template<typename T>
    void MergeMetadata(camera_metadata_item_t& entry, std::vector<T>& ohosTagVec)
    {
        uint32_t data_type;
        int32_t ret = GetCameraMetadataItemType(entry.item, &data_type);
        if (ret != CAM_META_SUCCESS) {
            return;
        }
        for (uint32_t i = 0; i < entry.count; i++) {
            if (data_type == META_TYPE_BYTE) {
                ohosTagVec.push_back(entry.data.u8[i]);
            } else if (data_type == META_TYPE_INT32) {
                ohosTagVec.push_back(entry.data.i32[i]);
            } else if (data_type == META_TYPE_FLOAT) {
                ohosTagVec.push_back(entry.data.f[i]);
            }
        }
    }

    template<typename T>
    void AddOrUpdateOhosTag(std::shared_ptr<CameraMetadata> metadata, int ohosTag, std::vector<T> ohosTagVec)
    {
        if (ohosTagVec.empty()) {
            return;
        }
        common_metadata_header_t *data = metadata->get();
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, ohosTag, &entry);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            if (!metadata->addEntry(ohosTag, ohosTagVec.data(), ohosTagVec.size())) {
                CAMERA_LOGE("%{public}s(%{public}d) add failed", GetCameraMetadataItemName(ohosTag), ohosTag);
                return;
            }
            CAMERA_LOGD("%{public}s(%{public}d) add success", GetCameraMetadataItemName(ohosTag), ohosTag);
        } else if (ret == CAM_META_SUCCESS) {
            MergeMetadata(entry, ohosTagVec);
            std::sort(ohosTagVec.begin(), ohosTagVec.end());
            if (!metadata->updateEntry(ohosTag, ohosTagVec.data(), ohosTagVec.size())) {
                CAMERA_LOGE("%{public}s(%{public}d) update failed", GetCameraMetadataItemName(ohosTag), ohosTag);
                return;
            }
            CAMERA_LOGD("%{public}s(%{public}d) update success", GetCameraMetadataItemName(ohosTag), ohosTag);
        }
    }

    void Convert3aLockToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void ConvertControlCaptureMirrorSupportedToOhos(std::shared_ptr<CameraMetadata> metadata,
                                                    const DeviceControl& deviceControl);
    void ConvertAbilityExposureModesToOhos(std::shared_ptr<CameraMetadata> metadata,
                                           const DeviceControl& deviceControl);
    void ConvertAbilityFocusModesToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void ConvertAbilityFlashModesToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void ConvertAbilityZoomRatioRangeToOhos(std::shared_ptr<CameraMetadata> metadata,
                                            const DeviceControl& deviceControl);
    void ConvertAbilityVideoStabilizationModesToOhos(std::shared_ptr<CameraMetadata> metadata);
    void ConvertAbilityFpsRangesToOhos(std::shared_ptr<CameraMetadata> metadata,
                                       std::vector<DeviceFormat>& deviceFormat);
    void ConvertAbilityStreamAvailableExtendConfigurationsToOhos(std::shared_ptr<CameraMetadata> metadata,
                                                                 const std::vector<DeviceFormat>& deviceFormat);
    void ConvertAbilityMeterModesToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void ConvertAbilityAWBModesToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void ConvertAbilityExposureTimeToOhos(std::shared_ptr<CameraMetadata> metadata, const DeviceControl& deviceControl);
    void AddDefaultSensorInfoPhysicalSize(std::shared_ptr<CameraMetadata> metadata,
                                          std::vector<DeviceFormat>& deviceFormat);
    void AddDefaultAbilityMuteModes(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultAbilityConcurrentCameras(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultControlCaptureMirrorSupport(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultCameraConnectionType(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultCameraPosition(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultCameraType(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultFlashAvailable(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultJpegOrientation(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultJpegQuality(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultAbilityStreamAvailableBasicConfigurations(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultSensorOrientation(std::shared_ptr<CameraMetadata> metadata);
    void AddDefaultFocalLength(std::shared_ptr<CameraMetadata> metadata);

private:
    HotplugDevCb uvcCb_ = nullptr;
    std::shared_ptr<EnumeratorManager> enumeratorManager_;
    std::vector<HardwareConfiguration> hardwareList_;
    std::vector<std::shared_ptr<IManager>> managerList_;
    std::mutex mtx_;
};
} // namespace OHOS::Camera
#endif
