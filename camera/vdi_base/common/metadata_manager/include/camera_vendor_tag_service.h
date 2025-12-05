/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_CAMERA_METADATA_V1_0_CAMERAVENDORTAGSERVICE_H
#define OHOS_HDI_CAMERA_METADATA_V1_0_CAMERAVENDORTAGSERVICE_H

#include "v1_0/icamera_vendor_tag.h"
#include "camera_device_ability_items.h"

namespace OHOS {
namespace HDI {
namespace Camera {
namespace Metadata {
namespace V1_0 {

enum ExampleVendorSection {
    EXAMPLE_VENDOR_SENSOR = OHOS_VENDOR_SECTION,
    EXAMPLE_VENDOR_SECTION_END
};

constexpr int EXAMPLE_SECTION_COUNT = EXAMPLE_VENDOR_SECTION_END - OHOS_VENDOR_SECTION;

enum vendor_extension_section_ranges {
    EXAMPLE_VENDOR_SENSOR_START = EXAMPLE_VENDOR_SENSOR << 16
};

// Define example vendor tags here.
enum ExampleVendorTags {
    EXAMPLE_VENDOR_SENSOR_MODE = EXAMPLE_VENDOR_SENSOR_START,
    EXAMPLE_VENDOR_SENSOR_EXPOSURE,
    EXAMPLE_VENDOR_SENSOR_END,
};

const uint32_t EXAMPLE_VENDOR_SECTION_BOUNDS[EXAMPLE_SECTION_COUNT][2] = {
    {(uint32_t)EXAMPLE_VENDOR_SENSOR_START, (uint32_t)EXAMPLE_VENDOR_SENSOR_END}
};

class CameraVendorTagService : public OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag {
public:
    CameraVendorTagService() = default;
    virtual ~CameraVendorTagService() = default;

    int32_t GetVendorTagName(uint32_t tagId, void*& tagName) override;

    int32_t GetVendorTagType(uint32_t tagId, int8_t& tagType) override;

    int32_t GetAllVendorTags(std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag>& tagVec) override;
};
} // V1_0
} // Metadata
} // Camera
} // HDI
} // OHOS

#endif // OHOS_HDI_CAMERA_METADATA_V1_0_CAMERAVENDORTAGSERVICE_H

