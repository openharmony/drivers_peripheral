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

#include "stream_still_capture.h"

namespace OHOS::Camera {
StreamStillCapture::StreamStillCapture()
{
}

StreamStillCapture::~StreamStillCapture()
{
    CAMERA_LOGV("enter");
}

RetCode StreamStillCapture::HandleOverStaticContext(const std::shared_ptr<OfflineStreamContext>& context)
{
    if (streamInfo_ == nullptr) {
        CAMERA_LOGE("can't handle over stream info");
        return RC_ERROR;
    }
    context->streamInfo = streamInfo_;

    if (bufferPool_ == nullptr) {
        CAMERA_LOGE("can't handle over buffer pool");
        return RC_ERROR;
    }
    context->bufferPool = bufferPool_;

    if (producer_ == nullptr) {
        CAMERA_LOGE("can't handle over buffer queue");
        return RC_ERROR;
    }
    context->bufferQueue = producer_;

    return RC_OK;
}

RetCode StreamStillCapture::HandleOverDynamicContext(const std::shared_ptr<OfflineStreamContext>& context)
{
    context->restBuffers = bufferMap_;

    context->restBufferCount = static_cast<uint32_t>(restBufferInOffline_);
    CAMERA_LOGI("there is/are %u buffer(s) left in stream %d.",
        context->restBufferCount, streamInfo_->streamId_);

    return RC_OK;
}

RetCode StreamStillCapture::SwitchToOffline()
{
    if (isOnline == false) {
        return RC_OK;
    }
    isOnline = false;
    restBufferInOffline_ = frameCount_;
    frameCount_ = 0;
    return RC_OK;
}

REGISTERSTREAM(StreamStillCapture, {"STILL_CAPTURE"});
} // namespace OHOS::Camera
