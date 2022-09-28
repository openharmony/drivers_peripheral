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

#ifndef MOCK_DISTRIBUTED_STREAM_OPERATOR_CALLBACK_H
#define MOCK_DISTRIBUTED_STREAM_OPERATOR_CALLBACK_H

#include "v1_0/istream_operator_callback.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::Camera::V1_0;
class MockDStreamOperatorCallback : public IStreamOperatorCallback {
public:
    MockDStreamOperatorCallback() = default;

    virtual ~MockDStreamOperatorCallback() = default;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override
    {
        return 0;
    }

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override
    {
        return 0;
    }

    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override
    {
        return 0;
    }

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // MOCK_DISTRIBUTED_STREAM_OPERATOR_CALLBACK_H