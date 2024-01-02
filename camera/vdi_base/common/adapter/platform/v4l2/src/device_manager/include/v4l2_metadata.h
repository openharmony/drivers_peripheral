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

#ifndef HOS_CAMERA_V4L2_METADATA_H
#define HOS_CAMERA_V4L2_METADATA_H

#include <map>
#include <linux/videodev2.h>
#include "camera_metadata_info.h"
#include "v4l2_common.h"

namespace OHOS::Camera {
const int NO_EXIST_TAG = -1;
const int CAMERA_3A_LOCK = -2;
struct MetadataTag {
    int v4l2Tag = NO_EXIST_TAG;
    int ohosTag = NO_EXIST_TAG;
};

const MetadataTag g_metadataTagList[] = {
    {V4L2_CID_HFLIP,                         OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED},
    {V4L2_CID_VFLIP,                         OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED},
    {V4L2_CID_3A_LOCK,                       CAMERA_3A_LOCK},
    {V4L2_CID_EXPOSURE_AUTO,                 OHOS_ABILITY_EXPOSURE_MODES},
    {V4L2_CID_FOCUS_AUTO,                    OHOS_ABILITY_FOCUS_MODES},
    {V4L2_CID_AUTO_FOCUS_START,              OHOS_ABILITY_FOCUS_MODES},
    {V4L2_CID_FOCUS_ABSOLUTE,                OHOS_ABILITY_FOCUS_MODES},
    {V4L2_CID_FLASH_LED_MODE,                OHOS_ABILITY_FLASH_MODES},
    {V4L2_CID_ZOOM_ABSOLUTE,                 OHOS_ABILITY_ZOOM_RATIO_RANGE},
    {V4L2_CID_IMAGE_STABILIZATION,           OHOS_ABILITY_VIDEO_STABILIZATION_MODES},
    {V4L2_CID_EXPOSURE_ABSOLUTE,             OHOS_ABILITY_EXPOSURE_TIME},
    {V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE,   OHOS_ABILITY_AWB_MODES},
    {V4L2_CID_EXPOSURE_METERING,             OHOS_ABILITY_METER_MODES},
};
} // namespace OHOS::Camera
#endif
