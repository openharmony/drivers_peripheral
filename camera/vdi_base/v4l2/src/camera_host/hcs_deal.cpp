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

#include "hcs_deal.h"
#include <stdlib.h>
#include <vector>
#include "hcs_dm_parser.h"
#include "metadata_enum_map.h"
#define STRTOL_BASE  10

namespace OHOS::Camera {
HcsDeal::HcsDeal(const std::string &pathName) : sPathName(pathName), pDevResIns(nullptr), pRootNode(nullptr) {}

HcsDeal::~HcsDeal()
{
    ReleaseHcsTree();
    pDevResIns = nullptr;
    pRootNode = nullptr;
}

void HcsDeal::SetHcsPathName(const std::string &pathName)
{
    sPathName = pathName;
}

RetCode HcsDeal::Init()
{
    ReleaseHcsTree();
    pDevResIns = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (pDevResIns == nullptr) {
        CAMERA_LOGE("get hcs interface failed.");
        return RC_ERROR;
    }

    CAMERA_LOGD("pathname = %{public}s", sPathName.c_str());
    SetHcsBlobPath(sPathName.c_str());
    pRootNode = pDevResIns->GetRootNode();
    if (pRootNode == nullptr) {
        CAMERA_LOGE("GetRootNode failed");
        return RC_ERROR;
    }
    if (pRootNode->name != nullptr) {
        CAMERA_LOGI("pRootNode = %{public}s", pRootNode->name);
    }

    DealHcsData();

    return RC_OK;
}

RetCode HcsDeal::DealHcsData()
{
    const struct DeviceResourceNode *cameraHostConfig = pDevResIns->GetChildNode(pRootNode, "camera_host_config");
    if (cameraHostConfig == nullptr) {
        return RC_ERROR;
    }
    if (pRootNode->name != nullptr) {
        CAMERA_LOGI("pRootNode = %{public}s", pRootNode->name);
    }
    if (cameraHostConfig->name == nullptr) {
        CAMERA_LOGW("cameraHostConfig->name is null");
        return RC_ERROR;
    }
    CAMERA_LOGD("cameraHostConfig = %{public}s", cameraHostConfig->name);

    const struct DeviceResourceNode *childNodeTmp = nullptr;
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(cameraHostConfig, childNodeTmp)
    {
        if (childNodeTmp != nullptr && childNodeTmp->name != nullptr) {
            std::string nodeName = std::string(childNodeTmp->name);
            CAMERA_LOGI("cameraHostConfig subnode name = %{public}s", nodeName.c_str());
            if (nodeName.find(std::string("ability"), 0) != std::string::npos) {
                DealCameraAbility(*childNodeTmp);
            }
        }
    }

    return RC_OK;
}

RetCode HcsDeal::DealCameraAbility(const struct DeviceResourceNode &node)
{
    CAMERA_LOGI("nodeName = %{public}s", node.name);

    const char *cameraId = nullptr;
    int32_t ret = pDevResIns->GetString(&node, "logicCameraId", &cameraId, nullptr);
    if (ret != 0) {
        CAMERA_LOGW("get logic cameraid failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("logic cameraid is %{public}s", cameraId);

    std::vector<std::string> phyCameraIds;
    (void)DealPhysicsCameraId(node, phyCameraIds);
    if (!phyCameraIds.empty() && cameraId != nullptr) {
        cameraIdMap_.insert(std::make_pair(std::string(cameraId), phyCameraIds));
    }

    const struct DeviceResourceNode *metadataNode = pDevResIns->GetChildNode(&node, "metadata");
    if (metadataNode == nullptr || cameraId == nullptr) {
        CAMERA_LOGW("metadataNode is null or cameraId is null");
        return RC_ERROR;
    }
    RetCode rc = DealMetadata(cameraId, *metadataNode);
    if (rc != RC_OK) {
        CAMERA_LOGW("deal metadata failed");
        return RC_ERROR;
    }

    for (CameraIdMap::iterator itr = cameraIdMap_.begin(); itr != cameraIdMap_.end(); ++itr) {
        CAMERA_LOGD("cameraId = %{public}s", itr->first.c_str());
        for (auto &str : itr->second) {
            CAMERA_LOGD("phyCameraId = %{public}s", str.c_str());
        }
    }

    return RC_OK;
}

RetCode HcsDeal::DealPhysicsCameraId(const struct DeviceResourceNode &node, std::vector<std::string> &cameraIds)
{
    const char *nodeValue = nullptr;
    int32_t elemNum = pDevResIns->GetElemNum(&node, "physicsCameraIds");
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetStringArrayElem(&node, "physicsCameraIds", i, &nodeValue, nullptr);
        cameraIds.push_back(std::string(nodeValue));
    }

    return RC_OK;
}

RetCode HcsDeal::DealMetadata(const std::string &cameraId, const struct DeviceResourceNode &node)
{
    struct DeviceResourceAttr *drAttr = nullptr;
    DEV_RES_NODE_FOR_EACH_ATTR(&node, drAttr) {}

    CAMERA_LOGD("metadata = %{public}s", node.name);
    const int ENTRY_CAPACITY = 30;
    const int DATA_CAPACITY = 2000;
    std::shared_ptr<CameraMetadata> metadata = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
    if (metadata == nullptr) {
        CAMERA_LOGE("metadata is nullptr cameraId: %{public}s, nodeName: %{public}s",
            cameraId.c_str(), node.name);
        return RC_ERROR;
    }
    DealAeAvailableAntiBandingModes(node, metadata);
    DealAeAvailableModes(node, metadata);
    DealAvailableFpsRange(node, metadata);
    DealCameraPosition(node, metadata);
    DealCameraType(node, metadata);
    DealCameraConnectionType(node, metadata);
    DealCameraMemoryType(node, metadata);
    DealCameraFaceDetectMaxNum(node, metadata);
    DealAeCompensationRange(node, metadata);
    DealAeCompensationSteps(node, metadata);
    DealAvailableAwbModes(node, metadata);
    DealSensitivityRange(node, metadata);
    DealFaceDetectMode(node, metadata);
    DealFocalLength(node, metadata);
    DealAvailableFocusModes(node, metadata);
    DealAvailableExposureModes(node, metadata);
    DealAvailableMetereModes(node, metadata);
    DealAvalialbleFlashModes(node, metadata);
    DealMirrorSupported(node, metadata);
    DealAvaliableBasicConfigurations(node, metadata);
    DealSensorOrientation(node, metadata);
    DealAvalialbleVideoStabilizationModes(node, metadata);
    DealAvalialbleFlash(node, metadata);
    DealAvalialbleAutoFocus(node, metadata);
    DealZoomRationRange(node, metadata);
    DealJpegOrientation(node, metadata);
    DealAvaliableExtendConfigurations(node, metadata);
    DealJpegQuality(node, metadata);
#ifdef V4L2_EMULATOR
    DealCameraFoldStatus(node, metadata);
    DealCameraFoldScreenType(node, metadata);
#endif
    cameraMetadataMap_.insert(std::make_pair(cameraId, metadata));
    return RC_OK;
}

RetCode HcsDeal::DealAeAvailableAntiBandingModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    std::vector<uint8_t> aeAvailableAntiBandingModeUint8s;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "aeAvailableAntiBandingModes");
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetStringArrayElem(&metadataNode, "aeAvailableAntiBandingModes", i, &nodeValue, nullptr);
        aeAvailableAntiBandingModeUint8s.push_back(AeAntibandingModeMap[std::string(nodeValue)]);
        CAMERA_LOGD("aeAvailableAntiBandingModes = %{public}s", nodeValue);
    }
    bool ret = metadata->addEntry(OHOS_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES, aeAvailableAntiBandingModeUint8s.data(),
        aeAvailableAntiBandingModeUint8s.size());
    if (!ret) {
        CAMERA_LOGE("aeAvailableAntiBandingModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("aeAvailableAntiBandingModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealAeAvailableModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t hcbRet = -1;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> aeAvailableModesU8;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "aeAvailableModes");
    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "aeAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGD("get aeAvailableModes failed");
            continue;
        }
        aeAvailableModesU8.push_back(AeModeMap[std::string(nodeValue)]);
        CAMERA_LOGD("aeAvailableModes = %{public}s", nodeValue);
    }
    bool ret =
        metadata->addEntry(OHOS_CONTROL_AE_AVAILABLE_MODES, aeAvailableModesU8.data(), aeAvailableModesU8.size());
    if (!ret) {
        CAMERA_LOGE("aeAvailableModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("aeAvailableModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableFpsRange(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t hcbRet = -1;
    uint32_t nodeValue;
    std::vector<int32_t> availableFpsRange;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "availableFpsRange");
    constexpr uint32_t groupLen = 2;

    if (elemNum != groupLen) {
        CAMERA_LOGE("availableFpsRange hcs file configuration error");
        return RC_ERROR;
    }

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetUint32ArrayElem(&metadataNode, "availableFpsRange", i, &nodeValue, -1);
        if (hcbRet != 0) {
            CAMERA_LOGD("get availableFpsRange failed");
            continue;
        }
        availableFpsRange.push_back(static_cast<int32_t>(nodeValue));
        CAMERA_LOGD("get availableFpsRange:%{public}d", nodeValue);
    }
    bool ret = metadata->addEntry(OHOS_ABILITY_FPS_RANGES, availableFpsRange.data(), availableFpsRange.size());
    if (!ret) {
        CAMERA_LOGE("availableFpsRange add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("availableFpsRange add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraPosition(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    CAMERA_LOGD("cameraPosition in...");
    const char *nodeValue = nullptr;
    uint8_t cameraPosition = 0;

    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraPosition", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraPosition failed");
        return RC_ERROR;
    }

    cameraPosition = CameraPositionMap[std::string(nodeValue)];
    CAMERA_LOGD("cameraPosition  = %{public}d", cameraPosition);

    bool ret = metadata->addEntry(
        OHOS_ABILITY_CAMERA_POSITION, static_cast<const void *>(&cameraPosition), sizeof(cameraPosition));
    if (!ret) {
        CAMERA_LOGE("cameraPosition add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("cameraPosition add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraType(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    CAMERA_LOGD("cameraType in...");
    const char *nodeValue = nullptr;
    uint8_t cameraType = 0;

    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraType", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraType failed");
        return RC_ERROR;
    }

    cameraType = CameraTypeMap[std::string(nodeValue)];
    CAMERA_LOGD("cameraType  = %{public}d", cameraType);

    bool ret = metadata->addEntry(OHOS_ABILITY_CAMERA_TYPE, static_cast<const void *>(&cameraType), sizeof(cameraType));
    if (!ret) {
        CAMERA_LOGE("cameraType add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("cameraType add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraConnectionType(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    CAMERA_LOGD("cameraConnectionType in...");
    const char *nodeValue = nullptr;
    uint8_t cameraConnectionType = 0;

    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraConnectionType", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraConnectionType failed");
        return RC_ERROR;
    }

    cameraConnectionType = cameraConnectionTypeMap[std::string(nodeValue)];
    CAMERA_LOGD("cameraConnectionType  = %{public}d", cameraConnectionType);

    bool ret = metadata->addEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, static_cast<const void *>(&cameraConnectionType),
        sizeof(cameraConnectionType));
    if (!ret) {
        CAMERA_LOGE("cameraConnectionType add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("cameraConnectionType add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraMemoryType(
    const struct DeviceResourceNode &metadataNode,
    std::shared_ptr<CameraMetadata> &metadata)
{
    CAMERA_LOGD("cameraMemoryType in...");
    const char *nodeValue = nullptr;
    uint8_t cameraMemoryType = 0;
    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraMemoryType", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraMemoryType failed");
        return RC_ERROR;
    }
    auto findIf = CameraMemoryTypeMap.find(std::string(nodeValue));
    if (findIf == CameraMemoryTypeMap.end()) {
        CAMERA_LOGE("value of cameraMemoryType err.[%{public}s]", nodeValue);
        return RC_ERROR;
    }
    cameraMemoryType = CameraMemoryTypeMap[std::string(nodeValue)];
    CAMERA_LOGD("cameraMemoryType  = %{public}d", cameraMemoryType);
    bool ret = metadata->addEntry(OHOS_ABILITY_MEMORY_TYPE,
        static_cast<const void*>(&cameraMemoryType), sizeof(cameraMemoryType));
    if (!ret) {
        CAMERA_LOGE("cameraMemoryType add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("cameraMemoryType add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraFaceDetectMaxNum(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    const char *pNodeValue = nullptr;
    uint8_t faceDetectMaxNum;

    int32_t rc = pDevResIns->GetString(&metadataNode, "faceDetectMaxNum", &pNodeValue, nullptr);
    if (rc != 0 || (pNodeValue == nullptr)) {
        CAMERA_LOGE("get faceDetectMaxNum failed");
        return RC_ERROR;
    }

    faceDetectMaxNum = (uint8_t)strtol(pNodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGD("faceDetectMaxNum  = %{public}f", faceDetectMaxNum);

    bool ret = metadata->addEntry(OHOS_STATISTICS_FACE_DETECT_MAX_NUM, static_cast<const void *>(&faceDetectMaxNum), 1);
    if (!ret) {
        CAMERA_LOGE("faceDetectMaxNum add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("faceDetectMaxNum add success");
    return RC_OK;
}

RetCode HcsDeal::DealAeCompensationRange(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    std::vector<int32_t> aeCompensationRange;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "aeCompensationRange");
    uint32_t nodeValue;
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetUint32ArrayElem(&metadataNode, "aeCompensationRange", i, &nodeValue, -1);
        aeCompensationRange.push_back(static_cast<int32_t>(nodeValue));
    }

    bool ret =
        metadata->addEntry(OHOS_ABILITY_AE_COMPENSATION_RANGE, aeCompensationRange.data(), aeCompensationRange.size());
    if (!ret) {
        CAMERA_LOGD("aeCompensationRange add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("aeCompensationRange add success");
    return RC_OK;
}

RetCode HcsDeal::DealAeCompensationSteps(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    constexpr const char *AE_COMPENSATION_STEPS = "aeCompensationSteps";
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, AE_COMPENSATION_STEPS);
    uint32_t nodeValue;
    camera_rational_t aeCompensationStep;
    constexpr uint32_t groupLen = 2;

    if (elemNum != groupLen) {
        CAMERA_LOGE("aeCompensationSteps hcs file configuration error");
        return RC_ERROR;
    }

    pDevResIns->GetUint32ArrayElem(&metadataNode, AE_COMPENSATION_STEPS, 0, &nodeValue, -1);
    aeCompensationStep.numerator = (int32_t)nodeValue;
    pDevResIns->GetUint32ArrayElem(&metadataNode, AE_COMPENSATION_STEPS, 1, &nodeValue, -1);
    aeCompensationStep.denominator = (int32_t)nodeValue;

    bool ret = metadata->addEntry(OHOS_ABILITY_AE_COMPENSATION_STEP, &aeCompensationStep, 1);
    if (!ret) {
        CAMERA_LOGE("aeCompensationSteps add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("aeCompensationSteps add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableAwbModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t hcbRet = -1;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> availableAwbModes;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "availableAwbModes");
    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "availableAwbModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGD("get availableAwbModes failed");
            continue;
        }
        availableAwbModes.push_back(AwbModeMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_CONTROL_AWB_AVAILABLE_MODES, availableAwbModes.data(), availableAwbModes.size());
    if (!ret) {
        CAMERA_LOGE("availableAwbModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("availableAwbModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealSensitivityRange(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    std::vector<int32_t> sensitivityRange;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "sensitivityRange");
    CAMERA_LOGD("sensitivityRange elemNum = %{public}d", elemNum);
    uint32_t nodeValue;
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetUint32ArrayElem(&metadataNode, "sensitivityRange", i, &nodeValue, -1);
        sensitivityRange.push_back(static_cast<int32_t>(nodeValue));
    }

    bool ret = metadata->addEntry(OHOS_SENSOR_INFO_SENSITIVITY_RANGE, sensitivityRange.data(), sensitivityRange.size());
    if (!ret) {
        CAMERA_LOGI("sensitivityRange add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("sensitivityRange add success");
    return RC_OK;
}

RetCode HcsDeal::DealFaceDetectMode(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    const char *pNodeValue = nullptr;
    int32_t rc = pDevResIns->GetString(&metadataNode, "faceDetectMode", &pNodeValue, nullptr);
    if (rc != 0) {
        CAMERA_LOGI("get faceDetectMode failed");
        return RC_ERROR;
    }

    bool ret = metadata->addEntry(OHOS_STATISTICS_FACE_DETECT_MODE, &(FaceDetectModeMap[std::string(pNodeValue)]), 1);
    if (!ret) {
        CAMERA_LOGI("faceDetectMode add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("faceDetectMode add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableResultKeys(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t hcbRet = -1;
    const char *nodeValue = nullptr;
    std::vector<int32_t> availableResultKeys;
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "availableResultKeys");
    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "availableResultKeys", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGI("get availableResultKeys failed");
            continue;
        }
        availableResultKeys.push_back(MetadataTagMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(
        OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, availableResultKeys.data(), availableResultKeys.size());
    if (!ret) {
        CAMERA_LOGI("availableResultKeys add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("availableResultKeys add success");
    return RC_OK;
}

RetCode HcsDeal::DealFocalLength(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *pNodeValue = nullptr;
    float focalLength;

    int32_t rc = pDevResIns->GetString(&metadataNode, "focalLength", &pNodeValue, nullptr);
    if (rc != 0 || (pNodeValue == nullptr)) {
        CAMERA_LOGE("get focalLength failed");
        return RC_ERROR;
    }

    focalLength = (float)strtol(pNodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGD("focalLength  = %{public}f", focalLength);

    bool ret = metadata->addEntry(OHOS_ABILITY_FOCAL_LENGTH, static_cast<const void *>(&focalLength), 1);
    if (!ret) {
        CAMERA_LOGE("focalLength add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("focalLength add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableFocusModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> focusAvailableModes;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "focusAvailableModes");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "focusAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get focusAvailableModes failed");
            continue;
        }
        CAMERA_LOGD("nodeValue = %{public}s", nodeValue);
        focusAvailableModes.push_back(FocusModeMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_ABILITY_FOCUS_MODES, focusAvailableModes.data(), focusAvailableModes.size());
    if (!ret) {
        CAMERA_LOGE("focusAvailableModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("focusAvailableModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableExposureModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> exposureModeResult;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "exposureAvailableModes");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "exposureAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get exposureModeResult failed");
            continue;
        }
        CAMERA_LOGD("nodeValue = %{public}s", nodeValue);
        exposureModeResult.push_back(ExposureModeMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_ABILITY_EXPOSURE_MODES, exposureModeResult.data(), exposureModeResult.size());
    if (!ret) {
        CAMERA_LOGE("exposureModeResult add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("exposureModeResult add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvailableMetereModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> meterModeResult;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "meterAvailableModes");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "meterAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get meterModeResult failed");
            continue;
        }
        CAMERA_LOGD("nodeValue = %{public}s", nodeValue);
        meterModeResult.push_back(meterModeMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_ABILITY_METER_MODES, meterModeResult.data(), meterModeResult.size());
    if (!ret) {
        CAMERA_LOGE("meterModeResult add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("meterModeResult add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvalialbleFlashModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> flashAvailableModeUint8s;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "flashAvailableModes");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "flashAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get flashAvailableModes failed");
            continue;
        }
        CAMERA_LOGD("nodeValue = %{public}s", nodeValue);
        flashAvailableModeUint8s.push_back(FlashModeMap[std::string(nodeValue)]);
    }
    bool ret =
        metadata->addEntry(OHOS_ABILITY_FLASH_MODES, flashAvailableModeUint8s.data(), flashAvailableModeUint8s.size());
    if (!ret) {
        CAMERA_LOGE("flashAvailableModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("flashAvailableModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealMirrorSupported(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    uint8_t mirrorSupportU8;

    int32_t rc = pDevResIns->GetString(&metadataNode, "mirrorSupported", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get mirrorSupported failed");
        return RC_ERROR;
    }

    mirrorSupportU8 = mirrorMap[std::string(nodeValue)];
    CAMERA_LOGD("mirrorSupportU8  = %{public}d", mirrorSupportU8);

    bool ret =
        metadata->addEntry(OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, static_cast<const void *>(&mirrorSupportU8), 1);
    if (!ret) {
        CAMERA_LOGE("mirrorSupported add failed");
        return RC_ERROR;
    }
    CAMERA_LOGD("mirrorSupported add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvaliableBasicConfigurations(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint32_t nodeValue;
    std::vector<int32_t> basicConfigAvaliableInt32s;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "basicAvailableConfigurations");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);

    constexpr int STREAM_INFO_ITEM_LENGTH = 3;
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetUint32ArrayElem(&metadataNode, "basicAvailableConfigurations", i, &nodeValue, -1);
        CAMERA_LOGD("nodeValue = %{public}d", nodeValue);

        if (i % STREAM_INFO_ITEM_LENGTH == 0) {
            basicConfigAvaliableInt32s.push_back(formatArray[static_cast<int32_t>(nodeValue) - 1]);
        } else {
            basicConfigAvaliableInt32s.push_back(static_cast<int32_t>(nodeValue));
        }
    }

    bool ret = metadata->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, basicConfigAvaliableInt32s.data(),
        basicConfigAvaliableInt32s.size());
    if (!ret) {
        CAMERA_LOGD("basicAvailableConfigurations add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("basicAvailableConfigurations add success");
    return RC_OK;
}

RetCode HcsDeal::DealSensorOrientation(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    int32_t sensorOrientation;

    int32_t rc = pDevResIns->GetString(&metadataNode, "sensorOrientationSupported", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get sensorOrientationSupported failed");
        return RC_ERROR;
    }

    sensorOrientation = (int32_t)strtol(nodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGI("sensorOrientation  = %{public}d", sensorOrientation);

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_SENSOR_ORIENTATION, static_cast<const void *>(&sensorOrientation), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("sensorOrientationSupported add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("sensorOrientationSupported add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvalialbleVideoStabilizationModes(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> videoStabilizationAvailableModes;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "videoStabilizationAvailableModes");
    CAMERA_LOGI("elemNum = %{public}d", elemNum);
    for (int i = 0; i < elemNum; i++) {
        hcbRet =
            pDevResIns->GetStringArrayElem(&metadataNode, "videoStabilizationAvailableModes", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get videoStabilizationAvailableModes failed");
            continue;
        }
        CAMERA_LOGI("nodeValue = %{public}s", nodeValue);
        videoStabilizationAvailableModes.push_back(videoStabilizationMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_ABILITY_VIDEO_STABILIZATION_MODES, videoStabilizationAvailableModes.data(),
        videoStabilizationAvailableModes.size());
    if (!ret) {
        CAMERA_LOGE("videoStabilizationAvailableModes add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("videoStabilizationAvailableModes add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvalialbleFlash(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    uint8_t flashAvailable;

    int32_t rc = pDevResIns->GetString(&metadataNode, "flashAvailable", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get flashAvailable failed");
        return RC_ERROR;
    }

    if (flashAvailableMap.count(std::string(nodeValue)) == 0) {
        CAMERA_LOGE("flashAvailable invalid argument");
        return RC_ERROR;
    }
    flashAvailable = flashAvailableMap[std::string(nodeValue)];
    CAMERA_LOGI("flashAvailable  = %{public}d", flashAvailable);

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_ABILITY_FLASH_AVAILABLE, static_cast<const void *>(&flashAvailable), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("flashAvailable add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("flashAvailable add success");
    return RC_OK;
}

RetCode HcsDeal::DealAvalialbleAutoFocus(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<uint8_t> afAvailable;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "afAvailable");
    CAMERA_LOGI("elemNum = %{public}d", elemNum);
    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "afAvailable", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get afAvailable failed");
            continue;
        }
        CAMERA_LOGI("nodeValue = %{public}s", nodeValue);
        if (AfModeMap.count(std::string(nodeValue)) == 0) {
            CAMERA_LOGE("afAvailable invalid argument");
            return RC_ERROR;
        }
        afAvailable.push_back(AfModeMap[std::string(nodeValue)]);
    }
    bool ret = metadata->addEntry(OHOS_CONTROL_AF_AVAILABLE_MODES, afAvailable.data(), afAvailable.size());
    if (!ret) {
        CAMERA_LOGE("afAvailable add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("afAvailable add success");
    return RC_OK;
}

RetCode HcsDeal::DealZoomRationRange(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    uint8_t hcbRet = 0;
    const char *nodeValue = nullptr;
    std::vector<float> zoomRatioRange;

    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "zoomRatioRange");
    CAMERA_LOGI("elemNum = %{public}d", elemNum);

    constexpr uint32_t GROUP_LEN = 2;
    if (elemNum % GROUP_LEN != 0) {
        CAMERA_LOGE("zoomRatioRange hcs file configuration error");
        return RC_ERROR;
    }

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetStringArrayElem(&metadataNode, "zoomRatioRange", i, &nodeValue, nullptr);
        if (hcbRet != 0) {
            CAMERA_LOGE("get zoomRatioRange failed");
            continue;
        }
        CAMERA_LOGI("nodeValue = %{public}s", nodeValue);
        zoomRatioRange.push_back((float)strtol(nodeValue, NULL, STRTOL_BASE));
    }

    for (int i = 0; i < elemNum - 1;) {
        if (zoomRatioRange[i + 1] < zoomRatioRange[i]) {
            CAMERA_LOGE("zoomRatioRange invalid argument");
            return RC_ERROR;
        }
        constexpr uint32_t INDEX_INTERVAL = 2;
        i = i + INDEX_INTERVAL;
    }

    bool ret = metadata->addEntry(OHOS_ABILITY_ZOOM_RATIO_RANGE, zoomRatioRange.data(), zoomRatioRange.size());
    if (!ret) {
        CAMERA_LOGE("zoomRatioRange add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("zoomRatioRange add success");
    return RC_OK;
}

RetCode HcsDeal::DealJpegOrientation(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    int32_t jpegOrientation;

    int32_t rc = pDevResIns->GetString(&metadataNode, "jpegOrientation", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get jpegOrientation failed");
        return RC_ERROR;
    }

    jpegOrientation = (int32_t)strtol(nodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGI("jpegOrientation  = %{public}d", jpegOrientation);

    if (jpegOrientation != OHOS_CAMERA_JPEG_ROTATION_0 && jpegOrientation != OHOS_CAMERA_JPEG_ROTATION_90 &&
        jpegOrientation != OHOS_CAMERA_JPEG_ROTATION_180 && jpegOrientation != OHOS_CAMERA_JPEG_ROTATION_270) {
        CAMERA_LOGE("jpegOrientation invalid argument");
        return RC_ERROR;
    }

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_JPEG_ORIENTATION, static_cast<const void *>(&jpegOrientation), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("jpegOrientation add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("jpegOrientation add success");
    return RC_OK;
}

RetCode HcsDeal::DealJpegQuality(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    int32_t jpegQuality;

    int32_t rc = pDevResIns->GetString(&metadataNode, "jpegQuality", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get jpegQuality failed");
        return RC_ERROR;
    }

    jpegQuality = (int32_t)strtol(nodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGI("jpegQuality  = %{public}d", jpegQuality);

    if (jpegQuality != OHOS_CAMERA_JPEG_LEVEL_LOW && jpegQuality != OHOS_CAMERA_JPEG_LEVEL_MIDDLE &&
        jpegQuality != OHOS_CAMERA_JPEG_LEVEL_HIGH) {
        CAMERA_LOGE("jpegQuality invalid argument");
        return RC_ERROR;
    }

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_JPEG_QUALITY, static_cast<const void *>(&jpegQuality), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("jpegQuality add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("jpegQuality add success");
    return RC_OK;
}

RetCode HcsDeal::GetMetadata(CameraMetadataMap &metadataMap) const
{
    metadataMap = cameraMetadataMap_;
    return RC_OK;
}

RetCode HcsDeal::GetCameraId(CameraIdMap &cameraIdMap) const
{
    cameraIdMap = cameraIdMap_;
    return RC_OK;
}

RetCode HcsDeal::DealAvaliableExtendConfigurations(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    int32_t elemNum = pDevResIns->GetElemNum(&metadataNode, "extendAvailableConfigurations");
    CAMERA_LOGD("elemNum = %{public}d", elemNum);
    if (elemNum <= 0) {
        CAMERA_LOGD("elemNum <= 0");
        return RC_ERROR;
    }

    int hcbRet;
    uint32_t nodeValue;
    std::vector<int32_t> extendConfigAvaliableInt32s;

    for (int i = 0; i < elemNum; i++) {
        hcbRet = pDevResIns->GetUint32ArrayElem(&metadataNode, "extendAvailableConfigurations", i, &nodeValue, -1);
        if (hcbRet != 0 && nodeValue != UINT32_MAX) {
            CAMERA_LOGE("get extendAvailableConfigurations failed");
            continue;
        }
        extendConfigAvaliableInt32s.push_back(static_cast<int32_t>(nodeValue));
        CAMERA_LOGD("nodeValue = %{public}u", nodeValue);
    }

    bool ret = metadata->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS,
        extendConfigAvaliableInt32s.data(), extendConfigAvaliableInt32s.size());
    if (!ret) {
        CAMERA_LOGD("extendAvailableConfigurations add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("extendAvailableConfigurations add success");
    return RC_OK;
}

#ifdef V4L2_EMULATOR
RetCode HcsDeal::DealCameraFoldStatus(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    int32_t cameraFoldStatus;

    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraFoldStatus", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraFoldStatus failed");
        return RC_ERROR;
    }

    cameraFoldStatus = (int32_t)strtol(nodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGI("cameraFoldStatus  = %{public}d", cameraFoldStatus);

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_ABILITY_CAMERA_FOLD_STATUS,
        static_cast<const void *>(&cameraFoldStatus), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("cameraFoldStatus add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("cameraFoldStatus add success");
    return RC_OK;
}

RetCode HcsDeal::DealCameraFoldScreenType(
    const struct DeviceResourceNode &metadataNode, std::shared_ptr<Camera::CameraMetadata> &metadata)
{
    const char *nodeValue = nullptr;
    int32_t cameraFoldScreenType;

    int32_t rc = pDevResIns->GetString(&metadataNode, "cameraFoldScreenType", &nodeValue, nullptr);
    if (rc != 0 || (nodeValue == nullptr)) {
        CAMERA_LOGE("get cameraFoldScreenType failed");
        return RC_ERROR;
    }

    cameraFoldScreenType = (int32_t)strtol(nodeValue, NULL, STRTOL_BASE);
    CAMERA_LOGI("cameraFoldScreenType  = %{public}d", cameraFoldScreenType);

    constexpr uint32_t DATA_COUNT = 1;
    bool ret = metadata->addEntry(OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE,
        static_cast<const void *>(&cameraFoldScreenType), DATA_COUNT);
    if (!ret) {
        CAMERA_LOGE("cameraFoldScreenType add failed");
        return RC_ERROR;
    }
    CAMERA_LOGI("cameraFoldScreenType add success");
    return RC_OK;
}
#endif
} // namespace OHOS::Camera
