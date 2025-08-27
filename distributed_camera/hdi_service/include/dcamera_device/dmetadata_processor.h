/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_CAMERA_METADATA_PROCESSOR_H
#define DISTRIBUTED_CAMERA_METADATA_PROCESSOR_H

#include <set>
#include <map>
#include <mutex>
#include <vector>
#include "constants.h"
#include "dcamera.h"
#include "cJSON.h"
#include "v1_1/dcamera_types.h"
#include "v1_0/types.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::HDI::DistributedCamera::V1_1;
class DMetadataProcessor {
public:
    DMetadataProcessor() = default;
    ~DMetadataProcessor() = default;
    DMetadataProcessor(const DMetadataProcessor &other) = delete;
    DMetadataProcessor(DMetadataProcessor &&other) = delete;
    DMetadataProcessor& operator=(const DMetadataProcessor &other) = delete;
    DMetadataProcessor& operator=(DMetadataProcessor &&other) = delete;

public:
    DCamRetCode InitDCameraAbility(const std::string &sinkAbilityInfo);
    DCamRetCode GetDCameraAbility(std::shared_ptr<CameraAbility> &ability);
    DCamRetCode SetMetadataResultMode(const ResultCallbackMode &mode);
    DCamRetCode GetEnabledMetadataResults(std::vector<MetaType> &results);
    DCamRetCode EnableMetadataResult(const std::vector<MetaType> &results);
    DCamRetCode DisableMetadataResult(const std::vector<MetaType> &results);
    DCamRetCode ResetEnableResults();
    DCamRetCode SaveResultMetadata(std::string resultStr);
    void UpdateResultMetadata(const uint64_t &resultTimestamp);
    void SetResultCallback(std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> &resultCbk);
    void PrintDCameraMetadata(const common_metadata_header_t *metadata);

private:
    struct ResolutionFpsPair {
        DCResolution resolution;
        DCFps fps;
        bool operator<(const ResolutionFpsPair& other) const
        {
            return resolution < other.resolution;
        }
    };
    DCResolution ParseSingleResolution(cJSON* resolutionItem);
    DCFps ParseSingleFps(cJSON* fpsItem);
    
    DCamRetCode InitDCameraDefaultAbilityKeys(const std::string &sinkAbilityInfo);
    DCamRetCode InitDCameraOutputAbilityKeys(const std::string &sinkAbilityInfo);
    DCamRetCode AddAbilityEntry(uint32_t tag, const void *data, size_t size);
    DCamRetCode UpdateAbilityEntry(uint32_t tag, const void *data, size_t size);
    void ConvertToCameraMetadata(common_metadata_header_t *&input,
        std::shared_ptr<OHOS::Camera::CameraMetadata> &output);
    void ResizeMetadataHeader(common_metadata_header_t *&header, uint32_t itemCapacity, uint32_t dataCapacity);
    void UpdateAllResult(const uint64_t &resultTimestamp);
    void UpdateOnChanged(const uint64_t &resultTimestamp);
    uint32_t GetDataSize(uint32_t type);
    void* GetMetadataItemData(const camera_metadata_item_t &item);
    std::map<int, std::vector<DCResolution>> GetDCameraSupportedFormats(const std::string &abilityInfo);
    void ParsePhotoFormats(cJSON* rootValue, std::map<int, std::vector<DCResolution>>& supportedFormats);
    void ParsePreviewFormats(cJSON* rootValue, std::map<int, std::vector<DCResolution>>& supportedFormats);
    void ParseVideoFormats(cJSON* rootValue, std::map<int, std::vector<DCResolution>>& supportedFormats);
    void ParseResolutionAndFpsPairs(std::vector<ResolutionFpsPair>& profilePairs, cJSON* resolutionArray,
        cJSON* fpsArray, const DCFps& defaultFps);
    void StoreSinkAndSrcFps(int format, const std::string rootNode, std::vector<DCFps> &fpsVec);
    void InitDcameraBaseAbility();
    void GetEachNodeSupportedResolution(std::vector<int>& formats, const std::string rootNode,
        std::map<int, std::vector<DCResolution>>& supportedFormats, cJSON* rootValue);
    void GetNodeSupportedResolution(int format, const std::string rootNode,
        std::map<int, std::vector<DCResolution>>& supportedFormats, cJSON* rootValue);
    void SetFpsRanges();
    void InitBasicConfigTag(std::map<int, std::vector<DCResolution>> &supportedFormats,
        std::vector<int32_t> &streamConfigs);
    void InitExtendConfigTag(std::map<int, std::vector<DCResolution>> &supportedFormats,
        std::vector<int32_t> &extendStreamConfigs);
    void AddConfigs(std::vector<int32_t> &sinkExtendStreamConfigs, int32_t format,
        int32_t width, int32_t height, const DCFps& fpsInfo);
    void StoreSinkAndSrcConfig(int format, const std::string rootNode, std::vector<DCResolution> &resolutionVec);
    cJSON* GetFormatObj(const std::string rootNode, cJSON* rootValue, std::string& formatStr);
    cJSON* GetNodeItemArray(const std::string& rootNode, const std::string& itemKey,
        const std::string& formatStr, cJSON* rootValue);
    bool GetInfoFromJson(const std::string& sinkAbilityInfo);
    void InitOutputAbilityWithoutMode(const std::string &sinkAbilityInfo);
    void UpdateAbilityTag(std::vector<int32_t> &streamConfigs, std::vector<int32_t> &extendStreamConfigs);

private:
    constexpr static uint32_t JSON_ARRAY_MAX_SIZE = 1000;
    constexpr static uint32_t PREVIEW_FPS = 0;
    constexpr static uint32_t PHOTO_FPS = 0;
    constexpr static uint32_t VIDEO_FPS = 30;
    constexpr static uint32_t EXTEND_PREVIEW = 0;
    constexpr static uint32_t EXTEND_VIDEO = 1;
    constexpr static uint32_t EXTEND_PHOTO = 2;
    constexpr static int32_t EXTEND_EOF = -1;
    constexpr static uint32_t ADD_MODE = 3;
    constexpr static uint32_t DEFAULT_EXTEND_SIZE = 1000;
    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> resultCallback_;
    std::shared_ptr<CameraAbility> dCameraAbility_;
    std::string protocolVersion_;
    std::string dCameraPosition_;
    DCResolution maxPreviewResolution_;
    DCResolution maxPhotoResolution_;
    ResultCallbackMode metaResultMode_;
    std::set<MetaType> allResultSet_;
    std::set<MetaType> enabledResultSet_;
    std::mutex producerMutex_;
    std::vector<int> sinkPhotoFormats_;
    std::map<int, std::vector<DCResolution>> sinkPhotoProfiles_;
    std::map<int, std::vector<DCResolution>> sinkPreviewProfiles_;
    std::map<int, std::vector<DCResolution>> sinkVideoProfiles_;

    std::map<int, std::vector<DCFps>> sinkPhotoFps_;
    std::map<int, std::vector<DCFps>> sinkPreviewFps_;
    std::map<int, std::vector<DCFps>> sinkVideoFps_;

    // The latest result metadata that received from the sink device.
    std::shared_ptr<OHOS::Camera::CameraMetadata> latestProducerMetadataResult_;

    // The latest result metadata that replied to the camera service.
    std::shared_ptr<OHOS::Camera::CameraMetadata> latestConsumerMetadataResult_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_METADATA_PROCESSOR_H