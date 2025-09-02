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
#ifndef OHOS_MOCK_DSTREAM_OPERATOR_H
#define OHOS_MOCK_DSTREAM_OPERATOR_H

#include "dstream_operator.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace DistributedHardware {
class MockDStreamOperator : public DStreamOperator {
public:
    MockDStreamOperator() : DStreamOperator(nullptr) {}

    MOCK_METHOD(DCamRetCode, SetOutputVal, (const DHBase&, const std::string&, const std::string&), (override));
    MOCK_METHOD(DCamRetCode, SetCallBack, (const sptr<HDI::Camera::V1_0::IStreamOperatorCallback>&), (override));
    MOCK_METHOD(DCamRetCode, SetCallBack_V1_2, (const sptr<HDI::Camera::V1_2::IStreamOperatorCallback>&), (override));
    MOCK_METHOD(DCamRetCode, SetCallBack_V1_3, (const sptr<HDI::Camera::V1_3::IStreamOperatorCallback>&), (override));
    MOCK_METHOD(void, SetDeviceCallback, (const ErrorCallback&, const ResultCallback&), (override));
    MOCK_METHOD(std::vector<int>, GetStreamIds, (), (override));
    MOCK_METHOD(DCamRetCode, AcquireBuffer, (int, DCameraBuffer&), (override));
    MOCK_METHOD(DCamRetCode, ShutterBuffer, (int, const DCameraBuffer&), (override));
    MOCK_METHOD(void, Release, (), (override));
};
}
}
#endif
