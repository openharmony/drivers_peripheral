/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CAMERA_HOST_HCS_DEAL_H
#define CAMERA_HOST_HCS_DEAL_H

#include <list>
#include <map>
#include <string>
#include "camera_metadata_info.h"
#include "device_resource_if.h"
#include "utils.h"

namespace OHOS::Camera {
class HcsDeal {
    using CameraIdMap = std::map<std::string, std::vector<std::string>>;
    using CameraMetadataMap = std::map<std::string, std::shared_ptr<CameraMetadata>>;

public:
    HcsDeal(const std::string &pathName);
    virtual ~HcsDeal();
    HcsDeal(const HcsDeal &other) = delete;
    HcsDeal(HcsDeal &&other) = delete;
    HcsDeal &operator=(const HcsDeal &other) = delete;
    HcsDeal &operator=(HcsDeal &&other) = delete;

public:
    void SetHcsPathName(const std::string &pathName);
    RetCode Init();
    RetCode GetMetadata(CameraMetadataMap &metadataMap) const;
    RetCode GetCameraId(CameraIdMap &cameraIdMap) const;

private:
    RetCode DealHcsData();
    void ChangeToMetadata();
    RetCode DealCameraAbility(const struct DeviceResourceNode &node);
    RetCode DealPhysicsCameraId(const struct DeviceResourceNode &node, std::vector<std::string> &cameraIds);
    RetCode DealMetadata(const std::string &cameraId, const struct DeviceResourceNode &node);

    RetCode DealAeAvailableAntiBandingModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAeAvailableModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealCameraPosition(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealCameraType(const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealCameraConnectionType(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealCameraFaceDetectMaxNum(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAvailableFpsRange(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAeCompensationRange(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAeCompensationSteps(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAvailableAwbModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealSensitivityRange(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealFaceDetectMode(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAvailableResultKeys(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealFocalLength(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvailableFocusModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvailableExposureModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvailableMetereModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvalialbleFlashModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealMirrorSupported(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvaliableBasicConfigurations(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealSensorOrientation(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvalialbleVideoStabilizationModes(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvalialbleFlash(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealAvalialbleAutoFocus(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealZoomRationRange(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealJpegOrientation(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealJpegQuality(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealCameraMemoryType(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata);
    RetCode DealAvaliableExtendConfigurations(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
#ifdef V4L2_EMULATOR
    RetCode DealCameraFoldStatus(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
    RetCode DealCameraFoldScreenType(
        const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata);
#endif

private:
    std::string sPathName;
    const struct DeviceResourceIface *pDevResIns;
    const struct DeviceResourceNode *pRootNode;
    CameraIdMap cameraIdMap_;
    CameraMetadataMap cameraMetadataMap_;
};
} // namespace OHOS::Camera
#endif /* CAMERA_HOST_HCS_DEAL_H */
