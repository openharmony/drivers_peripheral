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

#include "metadata_config.h"

namespace OHOS {
namespace Camera {
MetadataConfig::MetadataConfig()
{
    metadata_.clear();
}
MetadataConfig::~MetadataConfig() {}

bool MetadataConfig::UpdateSettingsConfig(int32_t streamId, bool isNew, const std::vector<int32_t> &updateKeys,
    const std::shared_ptr<CameraMetadata> &metaData)
{
    if (updateKeys.size() == 0) {
        CAMERA_LOGE("invalid size");
        return false;
    }

    if (metadata_.count(streamId) == 0) {
        std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
        metadata_[streamId] = meta;
    }

    common_metadata_header_t *data = metaData->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is null");
        return false;
    }

    bool result = false;
    for (auto it = updateKeys.cbegin(); it != updateKeys.cend(); it++) {
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, *it, &entry);
        if (ret != 0) {
            CAMERA_LOGE("get [%{public}d] error", *it);
            return false;
        }
        if (isNew) {
            result = metadata_[streamId]->addEntry(*it, static_cast<void*>(entry.data.u8), entry.count);
        } else {
            result = metadata_[streamId]->updateEntry(*it, static_cast<void*>(entry.data.u8), entry.count);
        }
        if (!result) {
            CAMERA_LOGE("add key: [%{public}d] failed", *it);
            return false;
        }
    }
    return result;
}

bool MetadataConfig::GetMetadata(int32_t streamId, std::shared_ptr<CameraMetadata> &metaData)
{
    if (streamId < 0 || metadata_.count(streamId) == 0) {
        return false;
    }
    metaData = metadata_[streamId];
    return true;
}

void MetadataConfig::GetDeviceDefaultMetadata(std::shared_ptr<CameraMetadata> &metaData)
{
    int32_t exposureCompensation = 1;
    constexpr uint32_t DATA_COUNT = 1;
    metaData->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &exposureCompensation, DATA_COUNT);

    uint8_t videoStabiliMode = OHOS_CAMERA_VIDEO_STABILIZATION_OFF;
    metaData->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, DATA_COUNT);

    uint8_t focusMode = 0;
    metaData->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, sizeof(focusMode));

    uint8_t meterMode = 1;
    metaData->addEntry(OHOS_CONTROL_METER_MODE, &meterMode, sizeof(meterMode));

    uint8_t flashMode = 1;
    metaData->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, sizeof(flashMode));
}
} // namespace Camera
} // namespace OHOS
