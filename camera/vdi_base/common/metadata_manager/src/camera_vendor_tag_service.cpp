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

#include "camera_vendor_tag_service.h"
#include "camera_metadata_operator.h"
#include "camera.h"
#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Camera {
namespace Metadata {
namespace V1_0 {

const vendorTag_t VENDOR_SENSOR[EXAMPLE_VENDOR_SENSOR_END -
        EXAMPLE_VENDOR_SENSOR_START] = {
    {EXAMPLE_VENDOR_SENSOR_MODE, "sensorMode", META_TYPE_BYTE},
    {EXAMPLE_VENDOR_SENSOR_EXPOSURE, "sensorExposure", META_TYPE_INT64}
};

const vendorTag_t* EXAMPLE_VENDOR_TAG_INFO[EXAMPLE_SECTION_COUNT] = {
    VENDOR_SENSOR
};

extern "C" ICameraVendorTag *CameraVendorTagImplGetInstance(void)
{
    return new (std::nothrow) CameraVendorTagService();
}

int32_t CameraVendorTagService::GetVendorTagName(uint32_t tagId, void*& tagName)
{
    CAMERA_LOGI("CameraVendorTagService::GetVendorTagName start");
    int32_t tag_section = (tagId >> 16) - OHOS_VENDOR_SECTION;
    if (tag_section < 0 || tag_section >= EXAMPLE_SECTION_COUNT ||
        tagId >= EXAMPLE_VENDOR_SECTION_BOUNDS[tag_section][1]) {
        CAMERA_LOGE("CameraVendorTagService::GetVendorTagName failed");
        return HDF_FAILURE;
    }
    int32_t tag_index = tagId & 0xFFFF;
    tagName = const_cast<void*>(static_cast<const void*>(EXAMPLE_VENDOR_TAG_INFO[tag_section][tag_index].tagName));
    return HDF_SUCCESS;
}

int32_t CameraVendorTagService::GetVendorTagType(uint32_t tagId, int8_t& tagType)
{
    CAMERA_LOGI("CameraVendorTagService::GetVendorTagType start");
    int32_t tag_section = (tagId >> 16) - OHOS_VENDOR_SECTION;
    if (tag_section < 0 || tag_section >= EXAMPLE_SECTION_COUNT ||
        tagId >= EXAMPLE_VENDOR_SECTION_BOUNDS[tag_section][1]) {
        CAMERA_LOGE("CameraVendorTagService::GetVendorTagType failed");
        return HDF_FAILURE;
    }
    int32_t tag_index = tagId & 0xFFFF;
    tagType = static_cast<int8_t>(EXAMPLE_VENDOR_TAG_INFO[tag_section][tag_index].tagType);
    return HDF_SUCCESS;
}

int32_t CameraVendorTagService::GetAllVendorTags(std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag>& tagVec)
{
    CAMERA_LOGI("CameraVendorTagService::GetAllVendorTags start");
    for (int32_t section = 0; section < EXAMPLE_SECTION_COUNT; section++) {
        uint32_t start = EXAMPLE_VENDOR_SECTION_BOUNDS[section][0];
        uint32_t end = EXAMPLE_VENDOR_SECTION_BOUNDS[section][1];
        for (uint32_t tag = start; tag < end; tag++) {
            VendorTag info {};
            info.tagId = tag;
            auto ret = GetVendorTagName(info.tagId, info.tagName);
            if (ret != HDF_SUCCESS) {
                CAMERA_LOGE("CameraVendorTagService::GetAllVendorTags GetVendorTagName failed");
                return HDF_FAILURE;
            }
            ret = GetVendorTagType(info.tagId, info.tagType);
            if (ret != HDF_SUCCESS) {
                CAMERA_LOGE("CameraVendorTagService::GetAllVendorTags GetVendorTagType failed");
                return HDF_FAILURE;
            }
            tagVec.push_back(info);
        }
    }
    return HDF_SUCCESS;
}

} // V1_0
} // Metadata
} // Camera
} // HDI
} // OHOS
