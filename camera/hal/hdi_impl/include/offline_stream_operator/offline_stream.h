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

#ifndef HOS_CAMERA_OFFLINE_STREAM_H
#define HOS_CAMERA_OFFLINE_STREAM_H

#include "camera.h"
#include "offline_stream_context.h"
#include "istream_operator_callback.h"
#include <condition_variable>
#include <mutex>

namespace OHOS::Camera {
class OfflineStream {
public:
    OfflineStream() = default;
    OfflineStream(int32_t id,
                  std::shared_ptr<OfflineStreamContext>& context,
                  OHOS::wptr<IStreamOperatorCallback>& callback);
    virtual ~OfflineStream();

    RetCode Init();
    RetCode CancelCapture(int32_t captureId);
    RetCode Release();
    bool CheckCaptureIdExist(int32_t captureId);

private:
    void ReceiveOfflineBuffer(std::shared_ptr<IBuffer>& buffer);
    RetCode ReturnBuffer(std::shared_ptr<IBuffer>& buffer);

private:
    int32_t streamId_ = -1;
    uint64_t frameCount_ = 0;
    int32_t currentCaptureId_ = -1;
    std::shared_ptr<OfflineStreamContext> context_ = {};
    OHOS::wptr<IStreamOperatorCallback> operatorCallback_ = nullptr;
    std::condition_variable cv_;
    std::mutex lock_;
};
} // namespace OHOS::Camera
#endif
