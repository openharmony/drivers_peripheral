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

#ifndef METADATA_CONFIG_H
#define METADATA_CONFIG_H

#include "device_manager_adapter.h"
#include <map>

namespace OHOS {
namespace Camera {
constexpr uint32_t DEVICE_STREAM_ID = 0;
constexpr uint32_t ENTRY_CAPACITY = 30;
constexpr uint32_t DATA_CAPACITY = 2000;

class MetadataConfig {
    using CameraMetadataMap = std::map<int32_t, std::shared_ptr<CameraMetadata>>;

public:
    MetadataConfig();
    ~MetadataConfig();

    bool UpdateSettingsConfig(int32_t streamId, bool isNew, const std::vector<int32_t> &updateKeys,
        const std::shared_ptr<CameraMetadata> &metaData);
    bool GetMetadata(int32_t streamId, std::shared_ptr<CameraMetadata> &metaData);
    void GetDeviceDefaultMetadata(std::shared_ptr<CameraMetadata> &metaData);

private:
    CameraMetadataMap metadata_;
};
} // namespace Camera
} // namespace OHOS
#endif /* METADATA_CONFIG_H */
