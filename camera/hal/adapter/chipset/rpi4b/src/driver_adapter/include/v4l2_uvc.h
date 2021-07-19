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
#ifndef HOS_CAMERA_V4L2_UVC_H
#define HOS_CAMERA_V4L2_UVC_H

#include <thread>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include "v4l2_common.h"
#if defined(V4L2_UTEST) || defined (V4L2_MAIN_TEST)
#include "v4l2_temp.h"
#else
#include <camera.h>
#endif

namespace OHOS::Camera {
class HosV4L2UVC {
public:
    HosV4L2UVC();
    ~HosV4L2UVC();

    RetCode V4L2UvcDetectInit(UvcCallback cb);
    void V4L2UvcDetectUnInit();

private:
    void V4L2UvcSearchCapability(const std::string devName, const std::string v4l2Device, bool inOut);
    RetCode V4L2UvcGetCap(const std::string v4l2Device, struct v4l2_capability& cap);
    void V4L2UvcMatchDev(const std::string      name, const std::string v4l2Device, bool inOut);
    RetCode V4L2UvcEnmeDevices();
    void loopUvcDevice();
};
} // namespace OHOS::Camera

#endif // HOS_CAMERA_V4L2_UVC_H
