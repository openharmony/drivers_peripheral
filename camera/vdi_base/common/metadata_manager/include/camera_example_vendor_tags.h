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

#ifndef CAMERA_EXAMPLE_VENDOR_TAGS_H
#define CAMERA_EXAMPLE_VENDOR_TAGS_H

#include "camera_vendor_tag.h"
#include <cstdint>
#include "camera_device_ability_items.h"

namespace OHOS::Camera {
// Define example vendor tag section, start with OHOS_VENDOR_SECTION.
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

class CameraVendorTagExample : public CameraVendorTag {
public:
    CameraVendorTagExample() {}
    virtual ~CameraVendorTagExample() = default;
    uint32_t GetVendorTagCount() override;
    const char* GetVendorTagName(const uint32_t tag) override;
    int32_t GetVendorTagType(const uint32_t tag) override;
    void GetAllVendorTags(std::vector<vendorTag_t>& tagVec) override;
};

extern "C" CameraVendorTagExample* CreateVendorTagImpl()
{
    return new CameraVendorTagExample();
}
}
#endif /* CAMERA_EXAMPLE_VENDOR_TAGS_H */
