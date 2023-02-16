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

#ifndef DISTRIBUTED_UT_STREAM_CONSUMER_H
#define DISTRIBUTED_UT_STREAM_CONSUMER_H

#include <surface.h>
#include "iconsumer_surface.h"
#include "v1_0/ioffline_stream_operator.h"

namespace OHOS {
namespace DistributedHardware {
class StreamConsumer {
public:
    StreamConsumer();
    ~StreamConsumer();

    sptr<OHOS::IBufferProducer> CreateProducer();

    class TestBuffersConsumerListener : public IBufferConsumerListener {
    public:
        TestBuffersConsumerListener()
        {
        }

        ~TestBuffersConsumerListener()
        {
        }

        void OnBufferAvailable()
        {
        }
    };

private:
    sptr<OHOS::IConsumerSurface> consumer_ = nullptr;
};
} // namespace OHOS
} // namespace DistributedHardware
#endif // DISTRIBUTED_UT_STREAM_CONSUMER_H
