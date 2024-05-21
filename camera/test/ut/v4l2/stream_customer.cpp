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

#include "stream_customer.h"
#include "video_key_info.h"

StreamCustomer::StreamCustomer() {}
StreamCustomer::~StreamCustomer() {}

void StreamCustomer::CamFrame(const std::function<void(const unsigned char *, uint32_t)> callback)
{
    CAMERA_LOGD("test:enter CamFrame thread ++ ");
    OHOS::Rect damage;
    int32_t flushFence = 0;
    int64_t timestamp = 0;
    constexpr uint32_t delayTime = 12000;

    do {
        OHOS::sptr<OHOS::SurfaceBuffer> buff = nullptr;
        consumer_->AcquireBuffer(buff, flushFence, timestamp, damage);
        if (buff != nullptr) {
            void* addr = buff->GetVirAddr();
            int32_t size = buff->GetSize();
            if (callback != nullptr) {
                callback(static_cast<const unsigned char*>(addr), size);
            }
            consumer_->ReleaseBuffer(buff, -1);
        }
        usleep(delayTime);
    } while (camFrameExit_ == 0);

    CAMERA_LOGD("test:Exiting CamFrame thread -- ");
}

OHOS::sptr<OHOS::IBufferProducer> StreamCustomer::CreateProducer()
{
    consumer_ = OHOS::IConsumerSurface::Create();
    if (consumer_ == nullptr) {
        return nullptr;
    }
    OHOS::sptr<OHOS::IBufferConsumerListener> listener = new TestBuffersConsumerListener();
    CHECK_IF_PTR_NULL_RETURN_VALUE(listener, nullptr);
    consumer_->RegisterConsumerListener(listener);

    auto producer = consumer_->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }

    CAMERA_LOGI("test, create a buffer queue producer");
    return producer;
}

OHOS::Camera::RetCode StreamCustomer::ReceiveFrameOn(
    const std::function<void(const unsigned char *, uint32_t)> callback)
{
    CAMERA_LOGD("test:ReceiveFrameOn enter");

    if (camFrameExit_ == 1) {
        camFrameExit_ = 0;
        previewThreadId_ = new (std::nothrow) std::thread(&StreamCustomer::CamFrame, this, callback);
        if (previewThreadId_ == nullptr) {
            CAMERA_LOGE("test:ReceiveFrameOn failed");
            return OHOS::Camera::RC_ERROR;
        }
    } else {
        CAMERA_LOGI("test:ReceiveFrameOn loop thread is running");
    }
    CAMERA_LOGD("test:ReceiveFrameOn exit");

    return OHOS::Camera::RC_OK;
}

void StreamCustomer::ReceiveFrameOff()
{
    CAMERA_LOGD("test:ReceiveFrameOff enter");

    if (camFrameExit_ == 0) {
        camFrameExit_ = 1;
        if (previewThreadId_ != nullptr) {
            previewThreadId_->join();
            delete previewThreadId_;
            previewThreadId_ = nullptr;
        }
    }

    CAMERA_LOGD("test:ReceiveFrameOff exit");
}
