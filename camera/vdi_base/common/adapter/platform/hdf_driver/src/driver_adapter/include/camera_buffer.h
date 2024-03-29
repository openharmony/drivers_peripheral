/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CAMERA_BUFFER_H
#define CAMERA_BUFFER_H

#include <unordered_map>
#include "camera_common.h"

namespace OHOS::Camera {
class CameraBuffer {
public:
    explicit CameraBuffer(enum CameraMemType memType);
    ~CameraBuffer();

    RetCode CameraInitMemory(struct CameraFeature feature);
    RetCode CameraReqMemory(struct CameraFeature feature, int unsigned buffCont);
    RetCode CameraAllocBuffer(struct CameraFeature feature, const std::shared_ptr<FrameSpec> &frameSpec);
    RetCode CameraQueryMemory(struct CameraFeature feature,
        struct UserCameraBuffer &userBuffer, enum CameraQueryMemeryFlags flag);
    RetCode CameraStreamQueue(struct CameraFeature feature, const std::shared_ptr<FrameSpec> &frameSpec);
    RetCode CameraStreamDequeue(struct CameraFeature feature);
    RetCode CameraReleaseBuffers(struct CameraFeature feature);
    void SetCameraBufferCallback(BufCallback cb);
    RetCode Flush(char *deviceName);

private:
    BufCallback dequeueBuffer_;
    std::unordered_map<uint32_t, std::shared_ptr<FrameSpec>> bufferMap;
    static const uint32_t planeCount_ = 1;
    std::vector<void *> mmapArray_;
    std::vector<uint32_t> offArray_;
    std::vector<uint32_t> lengthArray_;
    enum CameraMemType memoryType_;
};
} // namespace OHOS::Camera
#endif // CAMERA_BUFFER_H
