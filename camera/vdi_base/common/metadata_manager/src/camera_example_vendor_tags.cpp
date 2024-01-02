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

#include "camera_example_vendor_tags.h"

namespace OHOS::Camera {
const uint32_t EXAMPLE_VENDOR_SECTION_BOUNDS[EXAMPLE_SECTION_COUNT][2] = {
    {(uint32_t)EXAMPLE_VENDOR_SENSOR_START, (uint32_t)EXAMPLE_VENDOR_SENSOR_END}
};

const vendorTag_t VENDOR_SENSOR[EXAMPLE_VENDOR_SENSOR_END -
        EXAMPLE_VENDOR_SENSOR_START] = {
    {EXAMPLE_VENDOR_SENSOR_MODE, "sensorMode", META_TYPE_BYTE},
    {EXAMPLE_VENDOR_SENSOR_EXPOSURE, "sensorExposure", META_TYPE_INT64}
};

const vendorTag_t* EXAMPLE_VENDOR_TAG_INFO[EXAMPLE_SECTION_COUNT] = {
    VENDOR_SENSOR
};

uint32_t CameraVendorTagExample::GetVendorTagCount()
{
    uint32_t count = 0;

    for (int32_t section = 0; section < EXAMPLE_SECTION_COUNT; section++) {
        uint32_t start = EXAMPLE_VENDOR_SECTION_BOUNDS[section][0];
        uint32_t end = EXAMPLE_VENDOR_SECTION_BOUNDS[section][1];
        count += end - start;
    }
    return count;
}

const char* CameraVendorTagExample::GetVendorTagName(const uint32_t tag)
{
    int32_t tag_section = (tag >> 16) - OHOS_VENDOR_SECTION;
    if (tag_section < 0
            || tag_section >= EXAMPLE_SECTION_COUNT
            || tag >= EXAMPLE_VENDOR_SECTION_BOUNDS[tag_section][1]) return nullptr;
    int32_t tag_index = tag & 0xFFFF;
    return EXAMPLE_VENDOR_TAG_INFO[tag_section][tag_index].tagName;
}

int32_t CameraVendorTagExample::GetVendorTagType(const uint32_t tag)
{
    int32_t tag_section = (tag >> 16) - OHOS_VENDOR_SECTION;
    if (tag_section < 0
            || tag_section >= EXAMPLE_SECTION_COUNT
            || tag >= EXAMPLE_VENDOR_SECTION_BOUNDS[tag_section][1]) return -1;
    int32_t tag_index = tag & 0xFFFF;
    return EXAMPLE_VENDOR_TAG_INFO[tag_section][tag_index].tagType;
}

void CameraVendorTagExample::GetAllVendorTags(std::vector<vendorTag_t>& tagVec)
{
    for (int32_t section = 0; section < EXAMPLE_SECTION_COUNT; section++) {
        uint32_t start = EXAMPLE_VENDOR_SECTION_BOUNDS[section][0];
        uint32_t end = EXAMPLE_VENDOR_SECTION_BOUNDS[section][1];
        for (uint32_t tag = start; tag < end; tag++) {
            vendorTag_t info {};
            info.tagId = tag;
            info.tagName = GetVendorTagName(tag);
            info.tagType = GetVendorTagType(tag);
            tagVec.push_back(info);
        }
    }
}
}
