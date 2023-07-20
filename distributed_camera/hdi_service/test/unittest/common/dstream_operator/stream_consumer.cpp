/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "stream_consumer.h"

#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
StreamConsumer::StreamConsumer() {}
StreamConsumer::~StreamConsumer() {}

sptr<OHOS::IBufferProducer> StreamConsumer::CreateProducer()
{
    consumer_ = OHOS::IConsumerSurface::Create();
    if (consumer_ == nullptr) {
        return nullptr;
    }
    sptr<IBufferConsumerListener> listener(new TestBuffersConsumerListener());
    consumer_->RegisterConsumerListener(listener);

    auto producer = consumer_->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }

    DHLOGI("StreamConsumer test, create a buffer queue producer success");
    return producer;
}
}
}
