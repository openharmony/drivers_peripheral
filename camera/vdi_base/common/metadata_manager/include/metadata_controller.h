/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef METADATA_CONTROLLER_H
#define METADATA_CONTROLLER_H

#include "metadata_config.h"
#include <list>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>

namespace OHOS {
namespace Camera {
class MetadataController {
    using CameraNode = std::vector<std::function<void(std::shared_ptr<CameraMetadata>)>>;

public:
    static MetadataController &GetInstance();
    void SetUpdateSettingCallback(const MetaDataCb &cb);
    void UnSetUpdateSettingCallback();
    void AddNodeCallback(const MetaDataCb &cb);
    void ClearNodeCallback();
    void SetPeerFrameFlag(bool flag);
    void AddEnabledAbility(const std::vector<int32_t> &abilityMetaDataTag);
    int32_t GetEnabledAbility(std::vector<int32_t> &results);
    int32_t DelEnabledAbility(const std::vector<int32_t> &results);
    bool UpdateSettingsConfig(const std::shared_ptr<CameraMetadata> &meta);
    void GetSettingsConfig(std::shared_ptr<CameraMetadata> &meta);
    void NotifyMetaData(int32_t streamId);
    void SetDeviceDefaultMetadata(std::shared_ptr<CameraMetadata> &meta);
    void Start();
    void Stop();
    bool IsMute();

private:
    MetadataController();
    ~MetadataController();

    void DealMessage();
    void StopThread();
    int32_t GetStreamId(const std::shared_ptr<CameraMetadata> &meta);
    bool FilterUpdateKeys(int32_t streamId, const std::shared_ptr<CameraMetadata> &meta);
    bool DealMetadata(int32_t streamId, const std::shared_ptr<CameraMetadata> &meta);
    bool CompareMetadata(int32_t streamId, const std::shared_ptr<CameraMetadata> &oldMeta,
        const std::shared_ptr<CameraMetadata> &newMeta, std::shared_ptr<CameraMetadata> &outMetadata);
    bool UpdateChangeMetadata(int32_t streamId, const std::vector<int32_t> &updateKeys,
        const std::vector<int32_t> &newKeys, const std::shared_ptr<CameraMetadata> &newMeta,
        std::shared_ptr<CameraMetadata> &outMetadata);
    bool IsChangeTagData(int32_t key, const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool IsChangeU8Metadata(const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool IsChangeI32Metadata(const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool IsChangeI64Metadata(const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool IsChangeFloatMetadata(const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool IsChangeI32ArrayMetadata(const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry);
    bool UpdateNewTagData(const std::vector<int32_t> &keys, const std::shared_ptr<CameraMetadata> &inMeta,
        std::shared_ptr<CameraMetadata> &outMeta);
    bool DealUpdateNewTagData(
        const std::vector<int32_t> &keys, common_metadata_header_t *data, std::shared_ptr<CameraMetadata> &outMeta);

    std::shared_ptr<MetadataConfig> metaDataConfig_ = nullptr;
    MetaDataCb updateSettingFunc_;
    CameraNode nodeFunc_;
    std::unordered_set<int32_t> firstNotifyNodes_;
    std::map<int32_t, std::vector<int32_t>> updateMetaDataKeys_;
    std::map<int32_t, std::vector<int32_t>> changeDataKeys_;
    bool peerFrame_ = false;
    std::vector<int32_t> abilityMetaData_;
    std::mutex dataConfigLock_;
    std::mutex queueLock_;
    std::condition_variable cv_;
    std::queue<std::shared_ptr<CameraMetadata>> queue_;
    std::atomic_bool isRunning_;
    std::thread *notifyChangedMetadata_ = nullptr;
    bool isInit_ = false;
    bool isMute_ = false;
};
} // namespace Camera
} // namespace OHOS
#endif
