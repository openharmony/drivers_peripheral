/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_CAMERA_BUFFER_MANAGER_H
#define DISTRIBUTED_CAMERA_BUFFER_MANAGER_H

#include <list>
#include <mutex>

#include "constants.h"
#include "dimage_buffer.h"
#include "surface.h"
#include "surface_buffer.h"

#include "v1_1/dcamera_types.h"
#include "v1_0/display_composer_type.h"
#include "v1_1/display_composer_type.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedCamera::V1_1;
using namespace OHOS::HDI::Display::Composer::V1_0;
class DBufferManager {
public:
    DBufferManager() = default;
    virtual ~DBufferManager() = default;
    DBufferManager(const DBufferManager &other) = delete;
    DBufferManager(DBufferManager &&other) = delete;
    DBufferManager& operator=(const DBufferManager &other) = delete;
    DBufferManager& operator=(DBufferManager &&other) = delete;

public:
    std::shared_ptr<DImageBuffer> AcquireBuffer();
    RetCode AddBuffer(std::shared_ptr<DImageBuffer>& buffer);
    RetCode RemoveBuffer(std::shared_ptr<DImageBuffer>& buffer);
    void NotifyStop(bool state);
    static RetCode SurfaceBufferToDImageBuffer(const OHOS::sptr<OHOS::SurfaceBuffer> &surfaceBuffer,
        const std::shared_ptr<DImageBuffer> &buffer);
    static RetCode DImageBufferToDCameraBuffer(const std::shared_ptr<DImageBuffer> &imageBuffer,
        DCameraBuffer &buffer);
    static uint64_t CameraUsageToGrallocUsage(const uint64_t cameraUsage);
    static uint32_t PixelFormatToDCameraFormat(const OHOS::HDI::Display::Composer::V1_1::PixelFormat format);

private:
    std::mutex lock_;
    std::atomic_bool streamStop_ = false;
    std::list<std::shared_ptr<DImageBuffer>> idleList_ = {};
    std::list<std::shared_ptr<DImageBuffer>> busyList_ = {};
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_BUFFER_MANAGER_H