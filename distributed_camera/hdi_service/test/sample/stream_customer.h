/*
 * Copyright (c) 2022 - 2023 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_STREAM_CUSTOMER_H
#define DISTRIBUTED_STREAM_CUSTOMER_H

#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <surface.h>
#include "constants.h"
#include "distributed_hardware_log.h"
#include "iconsumer_surface.h"
#include "v1_0/ioffline_stream_operator.h"

namespace OHOS {
namespace DistributedHardware {

enum CaptureMode {
    CAPTURE_PREVIEW = 0,
    CAPTURE_SNAPSHOT,
    CAPTURE_VIDEO,
};

class TestBuffersConsumerListener : public IBufferConsumerListener {
public:
    TestBuffersConsumerListener(const sptr<IConsumerSurface>& surface,
        const std::function<void(void*, const uint32_t)> callback) : callback_(callback), consumer_(surface)
    {
    }

    ~TestBuffersConsumerListener()
    {
    }

    void OnBufferAvailable()
    {
        DHLOGI("demo test:enter OnBufferAvailable start");
        OHOS::Rect damage;
        int32_t flushFence = 0;
        int64_t timestamp = 0;

        OHOS::sptr<OHOS::SurfaceBuffer> buff = nullptr;
        consumer_->AcquireBuffer(buff, flushFence, timestamp, damage);
        if (buff != nullptr) {
            void* addr = buff->GetVirAddr();
            if (callback_ != nullptr) {
                int32_t size = buff->GetSize();
                callback_(addr, size);
            }
            consumer_->ReleaseBuffer(buff, -1);
            DHLOGI("demo test:Exiting OnBufferAvailable end");
        }
    }

private:
    std::function<void(void*, uint32_t)> callback_;
    sptr<IConsumerSurface> consumer_;
};

class StreamCustomer {
public:
    StreamCustomer();
    ~StreamCustomer();
    sptr<OHOS::IBufferProducer> CreateProducer(CaptureMode mode, const std::function<void(void*, uint32_t)> callback);

private:
    sptr<OHOS::IConsumerSurface> consumer_ = nullptr;
};

} // namespace OHOS::DistributedHardware
}
#endif // DISTRIBUTED_STREAM_CUSTOMER_H