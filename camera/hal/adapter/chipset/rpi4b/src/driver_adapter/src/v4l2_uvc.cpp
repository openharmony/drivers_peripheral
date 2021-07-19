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

#include "v4l2_uvc.h"
#include "securec.h"
#include "v4l2_control.h"
#include "v4l2_fileformat.h"
#include "v4l2_dev.h"

namespace OHOS::Camera {
HosV4L2UVC::HosV4L2UVC() {}
HosV4L2UVC::~HosV4L2UVC() {}

void HosV4L2UVC::V4L2UvcSearchCapability(const std::string devName, const std::string v4l2Device, bool inOut)
{
}

void HosV4L2UVC::V4L2UvcMatchDev(const std::string name, const std::string v4l2Device, bool inOut)
{
}

RetCode HosV4L2UVC::V4L2UvcGetCap(const std::string v4l2Device, struct v4l2_capability& cap)
{
    return RC_OK;
}

RetCode HosV4L2UVC::V4L2UvcEnmeDevices()
{
    return RC_OK;
}

void HosV4L2UVC::loopUvcDevice()
{
}

void HosV4L2UVC::V4L2UvcDetectUnInit()
{
}

RetCode HosV4L2UVC::V4L2UvcDetectInit(UvcCallback cb)
{
    return RC_OK;
}
} // namespace OHOS::Camera
