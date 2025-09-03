/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_ICAMERA_DEVICE_CALLBACK_H
#define OHOS_MOCK_ICAMERA_DEVICE_CALLBACK_H

#include "v1_0/icamera_device_callback.h"

namespace OHOS {
namespace HDI {
namespace Camera {
namespace V1_0 {

class MockCameraDeviceCallback : public ICameraDeviceCallback {
public:
    MockCameraDeviceCallback() = default;
    virtual ~MockCameraDeviceCallback() = default;

    int32_t OnError(ErrorType type, int32_t errorMsg) override
    {
        lastErrorType_ = type;
        lastErrorMsg_ = errorMsg;
        callCount_++;
        return 0;
    }

    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override
    {
        return 0;
    }

    ErrorType GetLastErrorType() const { return lastErrorType_; }
    int32_t GetCallCount() const { return callCount_; }
    void Reset()
    {
        lastErrorType_ = (ErrorType)-1;
        callCount_ = 0;
    }

private:
    ErrorType lastErrorType_ = (ErrorType)-1;
    int32_t lastErrorMsg_ = 0;
    int32_t callCount_ = 0;
};

} // V1_0
} // Camera
} // HDI
} // OHOS
#endif // OHOS_MOCK_ICAMERA_DEVICE_CALLBACK_H
