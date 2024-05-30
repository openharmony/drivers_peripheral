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

#include "v4l2_device_manager.h"
#include "isp_manager.h"
#include "flash_manager.h"
#include "sensor_manager.h"
#include "enumerator_manager.h"
#include "project_hardware.h"
#include "v4l2_metadata.h"

constexpr int ITEM_CAPACITY_SIZE = 30;
constexpr int DATA_CAPACITY_SIZE = 2000;

namespace OHOS::Camera {
IMPLEMENT_DEVICEMANAGER(V4L2DeviceManager);
V4L2DeviceManager::V4L2DeviceManager() {}

V4L2DeviceManager::~V4L2DeviceManager() {}

RetCode V4L2DeviceManager::Init()
{
    RetCode rc = RC_ERROR;
    std::vector<std::string> hardwareName;
    hardwareList_.clear();
    for (auto it = hardware.cbegin(); it != hardware.cend(); ++it) {
        if (it->controllerId == DM_C_SENSOR) {
            hardwareName.push_back(it->hardwareName);
            hardwareList_.push_back(*it);
        }
    }

    rc = HosV4L2Dev::Init(hardwareName);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("%s HosV4L2Dev Init fail", __FUNCTION__);
        return RC_ERROR;
    }

    rc = CreateManager();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("%s CreateManager fail", __FUNCTION__);
        return RC_ERROR;
    }
    enumeratorManager_ = std::make_shared<EnumeratorManager>();
    if (enumeratorManager_ == nullptr) {
        CAMERA_LOGE("%s Create EnumeratorManager fail", __FUNCTION__);
        return RC_ERROR;
    }
    rc = enumeratorManager_->Init();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("%s EnumeratorManager Init fail", __FUNCTION__);
        return rc;
    }
    return rc;
}

std::vector<CameraId> V4L2DeviceManager::GetCameraId()
{
    std::vector<CameraId> sensor_list;
    for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
        if ((*iter).controllerId == DM_C_SENSOR) {
            sensor_list.push_back((*iter).cameraId);
        }
    }
    return sensor_list;
};

RetCode V4L2DeviceManager::PowerUp(CameraId cameraId)
{
    if (CheckCameraIdList(cameraId) == false) {
        return RC_ERROR;
    }
    RetCode rc = RC_OK;
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        rc = (*iter)->PowerUp(CameraIdToHardware(cameraId, (*iter)->GetManagerId()));
        if (rc == RC_ERROR) {
            return RC_ERROR;
        }
    }
    return rc;
}

RetCode V4L2DeviceManager::PowerDown(CameraId cameraId)
{
    if (CheckCameraIdList(cameraId) == false) {
        return RC_ERROR;
    }
    RetCode rc = RC_OK;
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        rc = (*iter)->PowerDown(CameraIdToHardware(cameraId, (*iter)->GetManagerId()));
        if (rc == RC_ERROR) {
            return RC_ERROR;
        }
    }
    return rc;
}

std::shared_ptr<ISensor> V4L2DeviceManager::GetSensor(CameraId cameraId)
{
    for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
        if ((*iter).controllerId == DM_C_SENSOR && (*iter).cameraId == cameraId) {
            return (std::static_pointer_cast<SensorManager>(GetManager(DM_M_SENSOR)))->GetSensor((*iter).hardwareName);
        }
    }
    return nullptr;
}

std::shared_ptr<IManager> V4L2DeviceManager::GetManager(ManagerId managerId)
{
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        if ((*iter)->GetManagerId() == managerId) {
            return (*iter);
        }
    }
    return nullptr;
}
RetCode V4L2DeviceManager::CreateManager()
{
    RetCode rc = RC_OK;
    std::shared_ptr<IManager> manager = nullptr;
    for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
        if (CheckManagerList((*iter).managerId) == false) {
            switch ((*iter).managerId) {
                case DM_M_SENSOR:
                    manager = std::make_shared<SensorManager>(DM_M_SENSOR);
                    CHECK_IF_PTR_NULL_RETURN_VALUE(manager, RC_ERROR);
                    rc = CreateController((*iter).cameraId, manager, DM_M_SENSOR);
                    break;
                case DM_M_FLASH:
                    manager = std::make_shared<FlashManager>(DM_M_FLASH);
                    CHECK_IF_PTR_NULL_RETURN_VALUE(manager, RC_ERROR);
                    rc = CreateController((*iter).cameraId, manager, DM_M_FLASH);
                    break;
                case DM_M_ISP:
                    manager = std::make_shared<IspManager>(DM_M_ISP);
                    CHECK_IF_PTR_NULL_RETURN_VALUE(manager, RC_ERROR);
                    rc = CreateController((*iter).cameraId, manager, DM_M_ISP);
                    break;
                default:
                    break;
            }
            if (rc == RC_ERROR) {
                return RC_ERROR;
            } else {
                managerList_.push_back(manager);
        }
        }
    }
    return rc;
}
RetCode V4L2DeviceManager::DestroyManager()
{
    return RC_OK;
}
std::shared_ptr<IController> V4L2DeviceManager::GetController(CameraId cameraId, ManagerId managerId,
    ControllerId controllerId)
{
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        if ((*iter)->GetManagerId() == managerId) {
            return (*iter)->GetController(controllerId, CameraIdToHardware(cameraId, (*iter)->GetManagerId()));
        }
    }
    return nullptr;
}
RetCode V4L2DeviceManager::CreateController(CameraId cameraId, std::shared_ptr<IManager> manager, ManagerId managerId)
{
    RetCode rc = RC_OK;
    (void)cameraId;
    for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
        if ((*iter).managerId == managerId) {
            switch (managerId) {
                case DM_M_SENSOR:
                    rc = manager->CreateController((*iter).controllerId, (*iter).hardwareName);
                    break;
                case DM_M_FLASH:
                    rc = manager->CreateController((*iter).controllerId, (*iter).hardwareName);
                    break;
                case DM_M_ISP:
                    rc = manager->CreateController((*iter).controllerId, (*iter).hardwareName);
                    break;
                default:
                    break;
            }
        }
        if (RC_ERROR == rc) {
            return RC_ERROR;
        }
    }
    return rc;
}
RetCode V4L2DeviceManager::DestroyController()
{
    return RC_OK;
}

bool V4L2DeviceManager::CheckCameraIdList(CameraId cameraId)
{
    auto it = std::find_if (hardwareList_.cbegin(), hardwareList_.cend(),
        [&cameraId](const HardwareConfiguration &item) -> bool {
                return item.cameraId == cameraId;
            });

    return hardwareList_.cend() != it;
}

bool V4L2DeviceManager::CheckManagerList(ManagerId managerId)
{
    auto it = std::find_if (managerList_.cbegin(), managerList_.cend(),
        [&managerId](const std::shared_ptr<IManager> sptr) -> bool {
            return sptr->GetManagerId() == managerId;
        });

    return managerList_.cend() != it;
}

void V4L2DeviceManager::Configure(std::shared_ptr<CameraMetadata> meta)
{
    if (managerList_.size() != 0) {
        for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
            (*iter)->Configure(meta);
        }
    }
}

RetCode V4L2DeviceManager::SetFlashlight(FlashMode flashMode, bool enable, CameraId cameraId)
{
    if (cameraId == CAMERA_MAX) {
        return std::static_pointer_cast<FlashController>(
            GetController(CAMERA_FIRST, DM_M_FLASH, DM_C_FLASH))->SetFlashlight(flashMode, enable);
    } else {
        return std::static_pointer_cast<FlashController>(
            GetController(cameraId, DM_M_FLASH, DM_C_FLASH))->SetFlashlight(flashMode, enable);
    }
}

void V4L2DeviceManager::SetMetaDataCallBack(const MetaDataCb cb, CameraId cameraId)
{
    if (managerList_.size() == 0) {
        return;
    }
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        if ((*iter)->GetManagerId() == DM_M_SENSOR) {
            if (cameraId == CAMERA_MAX) {
                (std::static_pointer_cast<SensorManager>(*iter))->SetMetaDataCallBack(cb,
                    CameraIdToHardware(CAMERA_FIRST, DM_M_SENSOR));
            } else {
                (std::static_pointer_cast<SensorManager>(*iter))->SetMetaDataCallBack(cb,
                    CameraIdToHardware(cameraId, DM_M_SENSOR));
            }
        }
    }
}

void V4L2DeviceManager::SetAbilityMetaDataTag(std::vector<int32_t> abilityMetaDataTag)
{
    CAMERA_LOGI("V4L2DeviceManager %{public}s: line: %{public}d", __FUNCTION__, __LINE__);
    CameraId cameraId = CAMERA_FIRST;
    if (managerList_.size() == 0) {
        CAMERA_LOGE("%{public}s managerList_ size is 0.", __FUNCTION__);
        return;
    }

    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        if ((*iter)->GetManagerId() == DM_M_SENSOR) {
            if (cameraId == CAMERA_MAX) {
                (std::static_pointer_cast<SensorManager>(*iter))->SetAbilityMetaDataTag(abilityMetaDataTag,
                    CameraIdToHardware(CAMERA_FIRST, DM_M_SENSOR));
            } else {
                (std::static_pointer_cast<SensorManager>(*iter))->SetAbilityMetaDataTag(abilityMetaDataTag,
                    CameraIdToHardware(cameraId, DM_M_SENSOR));
            }
        }
    }
}

std::string V4L2DeviceManager::CameraIdToHardware(CameraId cameraId, ManagerId managerId)
{
    std::lock_guard<std::mutex> l(mtx_);
    for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
        if ((*iter).managerId == managerId && (*iter).cameraId == cameraId) {
            return (*iter).hardwareName;
        }
    }
    return nullptr;
}

void V4L2DeviceManager::SetHotplugDevCallBack(HotplugDevCb cb)
{
    uvcCb_ = cb;
    enumeratorManager_->SetCallBack([&](const std::string hardwareName, std::vector<DeviceControl>& deviceControl,
        std::vector<DeviceFormat>& deviceFormat, bool uvcState) {
        UvcCallBack(hardwareName, deviceControl, deviceFormat, uvcState);
    });
}

void V4L2DeviceManager::AddHardware(CameraId id, const std::string hardwareName)
{
    std::lock_guard<std::mutex> l(mtx_);
    HardwareConfiguration hardware;
    hardware.cameraId = id;
    hardware.managerId = DM_M_SENSOR;
    hardware.controllerId = DM_C_SENSOR;
    hardware.hardwareName = hardwareName;
    hardwareList_.push_back(hardware);
    hardware.cameraId = id;
    hardware.managerId = DM_M_ISP;
    hardware.controllerId = DM_C_ISP;
    hardware.hardwareName = std::string("isp");
    hardwareList_.push_back(hardware);
    hardware.cameraId = id;
    hardware.managerId = DM_M_FLASH;
    hardware.controllerId = DM_C_FLASH;
    hardware.hardwareName = std::string("flash");
    hardwareList_.push_back(hardware);
}

void V4L2DeviceManager::UvcCallBack(const std::string hardwareName, std::vector<DeviceControl>& deviceControl,
    std::vector<DeviceFormat>& deviceFormat, bool uvcState)
{
    if (uvcState) {
        if (deviceControl.empty() || deviceFormat.empty()) {
            CAMERA_LOGI("V4L2DeviceManager::UvcCallBack %{public}s is empty", hardwareName.c_str());
            return;
        }
        CAMERA_LOGI("uvc plug in %{public}s begin", hardwareName.c_str());
        CameraId id = ReturnEnableCameraId("");
        CHECK_IF_EQUAL_RETURN_VOID(id, CAMERA_MAX);
        RetCode rc = GetManager(DM_M_SENSOR)->CreateController(DM_C_SENSOR, hardwareName);
        CHECK_IF_EQUAL_RETURN_VOID(rc, RC_ERROR);

        AddHardware(id, hardwareName);
        std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(ITEM_CAPACITY_SIZE,
            DATA_CAPACITY_SIZE);
        CHECK_IF_PTR_NULL_RETURN_VOID(meta);

        Convert(deviceControl, deviceFormat, meta);
        CHECK_IF_PTR_NULL_RETURN_VOID(uvcCb_);

        uvcCb_(meta, uvcState, id);
        CAMERA_LOGI("uvc plug in %{public}s end", hardwareName.c_str());
    } else {
        CAMERA_LOGI("uvc plug out %{public}s begin", hardwareName.c_str());
        CameraId id = ReturnEnableCameraId(hardwareName);
        CHECK_IF_EQUAL_RETURN_VOID(id, CAMERA_MAX);
        CHECK_IF_PTR_NULL_RETURN_VOID(uvcCb_);
        
        for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend();) {
            if ((*iter).cameraId != id) {
                iter++;
                continue;
            }
            if ((*iter).hardwareName == hardwareName) {
                std::shared_ptr<CameraMetadata> meta =
                    std::make_shared<CameraMetadata>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
                CHECK_IF_PTR_NULL_RETURN_VOID(meta);
                uvcCb_(meta, uvcState, id);
            }
            {
                std::lock_guard<std::mutex> l(mtx_);
                iter = hardwareList_.erase(iter);
            }
        }
        CAMERA_LOGI("uvc plug out %{public}s end", hardwareName.c_str());
    }
}

CameraId V4L2DeviceManager::ReturnEnableCameraId(std::string hardwareName)
{
    if (hardwareName.size() != 0) {
        for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
            if (hardwareName == (*iter).hardwareName) {
                return (*iter).cameraId;
            }
        }
        return CAMERA_MAX;
    }
    bool enable = true;
    for (CameraId id = CAMERA_FIRST; id <= CAMERA_MAX - 0; id = (CameraId)(id + 1)) {
        for (auto iter = hardwareList_.cbegin(); iter != hardwareList_.cend(); iter++) {
            if ((*iter).cameraId == id) {
                enable = false;
                break;
            } else {
                enable = true;
            }
        }
        if (enable == true) {
            return id;
        }
    }
    if (enable == false) {
        return CAMERA_MAX;
    }
    return CAMERA_MAX;
}

void V4L2DeviceManager::SetMemoryType(uint8_t &memType)
{
    if (managerList_.size() == 0) {
        return;
    }
    for (auto iter = managerList_.cbegin(); iter != managerList_.cend(); iter++) {
        if ((*iter)->GetManagerId() == DM_M_SENSOR) {
            (std::static_pointer_cast<SensorManager>(*iter))->SetMemoryType(memType);
        }
    }
    return;
}

void V4L2DeviceManager::Convert(std::vector<DeviceControl>& deviceControlVec, std::vector<DeviceFormat>& deviceFormat,
    std::shared_ptr<CameraMetadata> cameraMetadata)
{
    CAMERA_LOGD("V4L2DeviceManager::Convert() start \n");
    if (cameraMetadata == nullptr) {
        CAMERA_LOGE("Invalid parameter metadata");
        return;
    }

    ConvertV4l2TagToOhos(deviceControlVec, deviceFormat, cameraMetadata);
    AddDefaultOhosTag(cameraMetadata, deviceFormat);
}

void V4L2DeviceManager::ConvertV4l2TagToOhos(std::vector<DeviceControl>& deviceControlVec,
    std::vector<DeviceFormat>& deviceFormat, std::shared_ptr<CameraMetadata> cameraMetadata)
{
    for (auto& it : deviceControlVec) {
        int ohosTag = GetOhosMetaTag(it.id);
        if (ohosTag != NO_EXIST_TAG) {
            ConvertEntryToOhos(cameraMetadata, ohosTag, it);
        }
    }

    ConvertAbilityFpsRangesToOhos(cameraMetadata, deviceFormat);
    ConvertAbilityStreamAvailableExtendConfigurationsToOhos(cameraMetadata, deviceFormat);
}

void V4L2DeviceManager::AddDefaultOhosTag(std::shared_ptr<CameraMetadata> cameraMetadata,
    std::vector<DeviceFormat>& deviceFormat)
{
    AddDefaultSensorInfoPhysicalSize(cameraMetadata, deviceFormat);
    AddDefaultAbilityMuteModes(cameraMetadata);
    AddDefaultControlCaptureMirrorSupport(cameraMetadata);
    AddDefaultCameraConnectionType(cameraMetadata);
    AddDefaultCameraPosition(cameraMetadata);
    AddDefaultCameraType(cameraMetadata);
    AddDefaultFlashAvailable(cameraMetadata);
    AddDefaultJpegOrientation(cameraMetadata);
    AddDefaultJpegQuality(cameraMetadata);
    AddDefaultAbilityStreamAvailableBasicConfigurations(cameraMetadata);
    AddDefaultSensorOrientation(cameraMetadata);
    AddDefaultFocalLength(cameraMetadata);
}

int V4L2DeviceManager::GetOhosMetaTag(uint32_t v4l2Tag)
{
    for (auto metatag : g_metadataTagList) {
        if (metatag.v4l2Tag == v4l2Tag) {
            return metatag.ohosTag;
        }
    }
    return NO_EXIST_TAG;
}

RetCode V4L2DeviceManager::ConvertEntryToOhos(std::shared_ptr<CameraMetadata> metadata, int ohosTag,
    const DeviceControl& deviceControl)
{
    switch (ohosTag) {
        case CAMERA_3A_LOCK: {
            Convert3aLockToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED: {
            ConvertControlCaptureMirrorSupportedToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_EXPOSURE_MODES: {
            ConvertAbilityExposureModesToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_FOCUS_MODES: {
            ConvertAbilityFocusModesToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_FLASH_MODES: {
            ConvertAbilityFlashModesToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_ZOOM_RATIO_RANGE: {
            ConvertAbilityZoomRatioRangeToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_VIDEO_STABILIZATION_MODES: {
            ConvertAbilityVideoStabilizationModesToOhos(metadata);
            break;
        }
        case OHOS_ABILITY_METER_MODES: {
            ConvertAbilityMeterModesToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_AWB_MODES: {
            ConvertAbilityAWBModesToOhos(metadata, deviceControl);
            break;
        }
        case OHOS_ABILITY_EXPOSURE_TIME: {
            ConvertAbilityExposureTimeToOhos(metadata, deviceControl);
            break;
        }
        default:
            CAMERA_LOGE("There is no corresponding tag transformation");
            break;
    }
    return RC_OK;
}

void V4L2DeviceManager::Convert3aLockToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> lockModeVector;
    std::vector<uint8_t> aeLockVector;
    std::vector<uint8_t> awbLockVector;
    const int EXPOSURE_MASK = 1 << 0;
    const int AWB_MASK = 1 << 1;
    const int FOCUS_MASK = 1 << 2;
    if (deviceControl.default_value & FOCUS_MASK) {
        lockModeVector.push_back(OHOS_CAMERA_FOCUS_MODE_LOCKED);
        AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FOCUS_MODES, lockModeVector);
        std::vector<uint8_t>().swap(lockModeVector);
    }
    if (deviceControl.default_value & EXPOSURE_MASK) {
        lockModeVector.push_back(OHOS_CAMERA_EXPOSURE_MODE_LOCKED);
        AddOrUpdateOhosTag(metadata, OHOS_ABILITY_EXPOSURE_MODES, lockModeVector);

        aeLockVector.push_back(OHOS_CAMERA_AE_LOCK_ON);
        aeLockVector.push_back(OHOS_CAMERA_AE_LOCK_OFF);
        AddOrUpdateOhosTag(metadata, OHOS_ABILITY_AE_LOCK, aeLockVector);
    }
    if (deviceControl.default_value & AWB_MASK) {
        awbLockVector.push_back(OHOS_CAMERA_AWB_LOCK_ON);
        awbLockVector.push_back(OHOS_CAMERA_AWB_LOCK_OFF);
        AddOrUpdateOhosTag(metadata, OHOS_ABILITY_AWB_LOCK, awbLockVector);
    }
}

void V4L2DeviceManager::ConvertControlCaptureMirrorSupportedToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    common_metadata_header_t *data = metadata->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        if (deviceControl.id == V4L2_CID_HFLIP || deviceControl.id == V4L2_CID_VFLIP) {
            std::vector<uint8_t> captureMirrorSupportedVector;
            captureMirrorSupportedVector.push_back(OHOS_CAMERA_MIRROR_ON);
            AddOrUpdateOhosTag(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, captureMirrorSupportedVector);
        }
    }
}

void V4L2DeviceManager::ConvertAbilityExposureModesToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> abilityExposureModesVector;

    for (int i = 0; i < deviceControl.menu.size(); i++) {
        if (deviceControl.menu[i].id != V4L2_CID_EXPOSURE_AUTO) {
            continue;
        }
        if (deviceControl.menu[i].index == V4L2_EXPOSURE_MANUAL) {
            abilityExposureModesVector.push_back(OHOS_CAMERA_EXPOSURE_MODE_MANUAL);
        } else if (deviceControl.menu[i].index == V4L2_EXPOSURE_AUTO) {
            abilityExposureModesVector.push_back(OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO);
        }
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_EXPOSURE_MODES, abilityExposureModesVector);
}

void V4L2DeviceManager::ConvertAbilityFocusModesToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> abilityFocusModesVector;

    if (deviceControl.id == V4L2_CID_FOCUS_ABSOLUTE) {
        abilityFocusModesVector.push_back(OHOS_CAMERA_FOCUS_MODE_MANUAL);
    } else if (deviceControl.id == V4L2_CID_FOCUS_AUTO) {
        abilityFocusModesVector.push_back(OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO);
    } else if (deviceControl.id == V4L2_CID_AUTO_FOCUS_START) {
        abilityFocusModesVector.push_back(OHOS_CAMERA_FOCUS_MODE_AUTO);
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FOCUS_MODES, abilityFocusModesVector);
}

void V4L2DeviceManager::ConvertAbilityFlashModesToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> flashModesVector;

    for (int i = 0; i < deviceControl.menu.size(); i++) {
        if (deviceControl.menu[i].id != V4L2_CID_FLASH_LED_MODE) {
            continue;
        }
        if (deviceControl.menu[i].index == V4L2_FLASH_LED_MODE_NONE) {
            flashModesVector.push_back(OHOS_CAMERA_FLASH_MODE_CLOSE);
        } else if (deviceControl.menu[i].index == V4L2_FLASH_LED_MODE_FLASH) {
            flashModesVector.push_back(OHOS_CAMERA_FLASH_MODE_AUTO);
        } else if (deviceControl.menu[i].index == V4L2_FLASH_LED_MODE_TORCH) {
            flashModesVector.push_back(OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN);
        }
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FLASH_MODES, flashModesVector);
}

void V4L2DeviceManager::ConvertAbilityZoomRatioRangeToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    const float FACTOR = 100.0;
    std::vector<float> zoomRangeVector;
    zoomRangeVector.push_back(deviceControl.minimum / FACTOR);
    zoomRangeVector.push_back(deviceControl.maximum / FACTOR);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_ZOOM_RATIO_RANGE, zoomRangeVector);
}

void V4L2DeviceManager::ConvertAbilityVideoStabilizationModesToOhos(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> videoStabilizationModesVector;
    videoStabilizationModesVector.push_back(OHOS_CAMERA_VIDEO_STABILIZATION_OFF);
    videoStabilizationModesVector.push_back(OHOS_CAMERA_VIDEO_STABILIZATION_LOW);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, videoStabilizationModesVector);
}

void V4L2DeviceManager::ConvertAbilityFpsRangesToOhos(std::shared_ptr<CameraMetadata> metadata,
    std::vector<DeviceFormat>& deviceFormat)
{
    std::set<int32_t> fpsSet;
    for (auto& it : deviceFormat) {
        int32_t fpsValue = it.fmtdesc.fps.denominator / it.fmtdesc.fps.numerator;
        fpsSet.insert(fpsValue);
    }

    std::vector<int32_t> fpsRangesVector;
    fpsRangesVector.push_back(*fpsSet.begin());
    fpsRangesVector.push_back(*fpsSet.rbegin());
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FPS_RANGES, fpsRangesVector);
}

void V4L2DeviceManager::ConvertAbilityStreamAvailableExtendConfigurationsToOhos(
    std::shared_ptr<CameraMetadata> metadata, const std::vector<DeviceFormat>& deviceFormat)
{
    const int END_SYMBOL = -1;
    const int MINIMUM_FPS = 5;
    const int PREVIEW_STREAM = 0;
    const int CAPTURE_STREAM = 2;
    const int VIDEO_STREAM = 1;
    const int FORMAT = 1;
    std::string name = "YUYV 4:2:2";
    std::vector<int32_t> formatVector;
    int32_t fpsValue = 0;
    for (auto& it : deviceFormat) {
        if (it.fmtdesc.description != name || it.fmtdesc.fps.numerator == 0) {
            continue;
        }
        fpsValue = it.fmtdesc.fps.denominator / it.fmtdesc.fps.numerator;
        if (fpsValue > MINIMUM_FPS) {
            formatVector.push_back(FORMAT);
            formatVector.push_back(it.fmtdesc.width);
            formatVector.push_back(it.fmtdesc.height);
            formatVector.push_back(fpsValue);
            formatVector.push_back(fpsValue);
            formatVector.push_back(fpsValue);
            formatVector.push_back(END_SYMBOL);
        }
    }
    formatVector.push_back(END_SYMBOL);

    std::vector<int32_t> streamAvailableExtendConfigurationsVector;
    streamAvailableExtendConfigurationsVector.push_back(0);
    streamAvailableExtendConfigurationsVector.push_back(PREVIEW_STREAM);
    streamAvailableExtendConfigurationsVector.insert(streamAvailableExtendConfigurationsVector.end(),
                                                     formatVector.begin(), formatVector.end());
    streamAvailableExtendConfigurationsVector.push_back(CAPTURE_STREAM);
    streamAvailableExtendConfigurationsVector.insert(streamAvailableExtendConfigurationsVector.end(),
                                                     formatVector.begin(), formatVector.end());
    streamAvailableExtendConfigurationsVector.push_back(VIDEO_STREAM);
    streamAvailableExtendConfigurationsVector.insert(streamAvailableExtendConfigurationsVector.end(),
                                                     formatVector.begin(), formatVector.end());
    streamAvailableExtendConfigurationsVector.push_back(END_SYMBOL);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS,
                       streamAvailableExtendConfigurationsVector);
}

void V4L2DeviceManager::ConvertAbilityMeterModesToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> abilityMeterModesVector;

    for (int i = 0; i < deviceControl.menu.size(); i++) {
        if (deviceControl.menu[i].id != V4L2_CID_EXPOSURE_METERING) {
            continue;
        }
        if (deviceControl.menu[i].index == V4L2_EXPOSURE_METERING_SPOT) {
            abilityMeterModesVector.push_back(OHOS_CAMERA_SPOT_METERING);
        } else if (deviceControl.menu[i].index == V4L2_EXPOSURE_METERING_MATRIX) {
            abilityMeterModesVector.push_back(OHOS_CAMERA_REGION_METERING);
        } else if (deviceControl.menu[i].index == V4L2_EXPOSURE_METERING_AVERAGE) {
            abilityMeterModesVector.push_back(OHOS_CAMERA_OVERALL_METERING);
        }
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_METER_MODES, abilityMeterModesVector);
}

void V4L2DeviceManager::ConvertAbilityAWBModesToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<uint8_t> abilityAWBModesVector;

    for (int i = 0; i < deviceControl.menu.size(); i++) {
        if (deviceControl.menu[i].id != V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE) {
            continue;
        }
        if (deviceControl.menu[i].index == V4L2_WHITE_BALANCE_MANUAL) {
            abilityAWBModesVector.push_back(OHOS_CAMERA_AWB_MODE_OFF);
        } else if (deviceControl.menu[i].index == V4L2_WHITE_BALANCE_AUTO) {
            abilityAWBModesVector.push_back(OHOS_CAMERA_AWB_MODE_AUTO);
        } else if (deviceControl.menu[i].index == V4L2_WHITE_BALANCE_DAYLIGHT) {
            abilityAWBModesVector.push_back(OHOS_CAMERA_AWB_MODE_DAYLIGHT);
        } else if (deviceControl.menu[i].index == V4L2_WHITE_BALANCE_CLOUDY) {
            abilityAWBModesVector.push_back(OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT);
        } else if (deviceControl.menu[i].index == V4L2_WHITE_BALANCE_SHADE) {
            abilityAWBModesVector.push_back(OHOS_CAMERA_AWB_MODE_SHADE);
        }
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_AWB_MODES, abilityAWBModesVector);
}

void V4L2DeviceManager::ConvertAbilityExposureTimeToOhos(std::shared_ptr<CameraMetadata> metadata,
    const DeviceControl& deviceControl)
{
    std::vector<int32_t> abilityExposureTimeVector;

    if (deviceControl.id == V4L2_CID_EXPOSURE_ABSOLUTE) {
        abilityExposureTimeVector.push_back(deviceControl.minimum);
        CAMERA_LOGE("V4L2DeviceManager::ConvertAbilityExposureTimeToOhos deviceControl.maximum is %{public}d",
            deviceControl.maximum);
        abilityExposureTimeVector.push_back(deviceControl.maximum);
    }

    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_EXPOSURE_TIME, abilityExposureTimeVector);
}

void V4L2DeviceManager::AddDefaultSensorInfoPhysicalSize(std::shared_ptr<CameraMetadata> metadata,
    std::vector<DeviceFormat>& deviceFormat)
{
    std::vector<float> physicalSize;
    for (auto iter = deviceFormat.cbegin(); iter != deviceFormat.cend(); iter++) {
        physicalSize.push_back((*iter).fmtdesc.width);
        physicalSize.push_back((*iter).fmtdesc.height);
    }
    AddOrUpdateOhosTag(metadata, OHOS_SENSOR_INFO_PHYSICAL_SIZE, physicalSize);
}

void V4L2DeviceManager::AddDefaultAbilityMuteModes(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> muteModesVector;
    muteModesVector.push_back(OHOS_CAMERA_MUTE_MODE_OFF);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_MUTE_MODES, muteModesVector);
}

void V4L2DeviceManager::AddDefaultControlCaptureMirrorSupport(std::shared_ptr<CameraMetadata> metadata)
{
    common_metadata_header_t *data = metadata->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        std::vector<uint8_t> controlCaptureMirrorSupportedVector;
        controlCaptureMirrorSupportedVector.push_back(OHOS_CAMERA_MIRROR_OFF);
        AddOrUpdateOhosTag(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, controlCaptureMirrorSupportedVector);
    }
}

void V4L2DeviceManager::AddDefaultCameraConnectionType(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> cameraConnectionTypeVector;
    cameraConnectionTypeVector.push_back(OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, cameraConnectionTypeVector);
}

void V4L2DeviceManager::AddDefaultCameraPosition(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> cameraPositionVector;
    cameraPositionVector.push_back(OHOS_CAMERA_POSITION_OTHER);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_CAMERA_POSITION, cameraPositionVector);
}

void V4L2DeviceManager::AddDefaultCameraType(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> cameraTypeVector;
    cameraTypeVector.push_back(OHOS_CAMERA_TYPE_UNSPECIFIED);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_CAMERA_TYPE, cameraTypeVector);
}

void V4L2DeviceManager::AddDefaultFlashAvailable(std::shared_ptr<CameraMetadata> metadata)
{
    common_metadata_header_t *data = metadata->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FLASH_MODES, &entry);
    std::vector<uint8_t> flashAvailableVector;
    flashAvailableVector.push_back((ret == CAM_META_SUCCESS) ? OHOS_CAMERA_FLASH_TRUE : OHOS_CAMERA_FLASH_FALSE);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FLASH_AVAILABLE, flashAvailableVector);
}

void V4L2DeviceManager::AddDefaultJpegOrientation(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<int32_t> jpegOrientationVector;
    jpegOrientationVector.push_back(OHOS_CAMERA_JPEG_ROTATION_0);
    AddOrUpdateOhosTag(metadata, OHOS_JPEG_ORIENTATION, jpegOrientationVector);
}

void V4L2DeviceManager::AddDefaultJpegQuality(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> jpegQualityVector;
    jpegQualityVector.push_back(OHOS_CAMERA_JPEG_LEVEL_HIGH);
    AddOrUpdateOhosTag(metadata, OHOS_JPEG_QUALITY, jpegQualityVector);
}

void V4L2DeviceManager::AddDefaultAbilityStreamAvailableBasicConfigurations(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> abilityStreamAvailableBasicConfigurationsVector;
    abilityStreamAvailableBasicConfigurationsVector.push_back(OHOS_CAMERA_FORMAT_RGBA_8888);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS,
                       abilityStreamAvailableBasicConfigurationsVector);
}

void V4L2DeviceManager::AddDefaultSensorOrientation(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<uint8_t> sensorOrientationVector;
    const uint8_t sensorOrientation = 0;
    sensorOrientationVector.push_back(sensorOrientation);
    AddOrUpdateOhosTag(metadata, OHOS_SENSOR_ORIENTATION, sensorOrientationVector);
}

void V4L2DeviceManager::AddDefaultFocalLength(std::shared_ptr<CameraMetadata> metadata)
{
    std::vector<float> cameraFocalLength;
    const float focalLength = 24.0;
    cameraFocalLength.push_back(focalLength);
    AddOrUpdateOhosTag(metadata, OHOS_ABILITY_FOCAL_LENGTH, cameraFocalLength);
}
} // namespace OHOS::Camera
