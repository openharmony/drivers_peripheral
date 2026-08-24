/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iremote_object.h>
#include <iremote_broker.h>
#include <peer_holder.h>
#include "stream_operator_service_callback.h"
#include "camera_service_type_converter.h"
#include "v1_0/istream_operator_callback.h"
#include "iproxy_broker.h"

using namespace OHOS::Camera;
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;
using namespace testing::ext;

// IStreamOperatorCallback stub via IProxyBroker(nullptr).
// hdi_objcast returns null, so AddDeathRecipient is skipped in constructor.
// streamOperatorCallback_ remains non-null, forwarding still works.
class TestStreamOperatorCallback
    : public OHOS::HDI::IProxyBroker<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback> {
public:
    TestStreamOperatorCallback() : IProxyBroker(nullptr), callCount_(0) {}

    bool IsProxy() override { return true; }

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override
    {
        callCount_++;
        return 0;
    }

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override
    {
        callCount_++;
        return 0;
    }

    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override
    {
        callCount_++;
        return 0;
    }

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        callCount_++;
        return 0;
    }

    int GetCallCount() const { return callCount_; }

private:
    int callCount_;
};

class StreamCallbackDeathTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: OnCallbackDied_BlocksAllForwarding
 * @tc.desc: After OnCallbackDied, all forwarding methods return INVALID_ARGUMENT.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(StreamCallbackDeathTest, OnCallbackDied_BlocksAllForwarding, TestSize.Level0)
{
    auto testCb = sptr<TestStreamOperatorCallback>(new TestStreamOperatorCallback());

    auto serviceCb = sptr<StreamOperatorServiceCallback>(
        new StreamOperatorServiceCallback(testCb));

    // Simulate remote process death
    serviceCb->OnCallbackDied();

    // All forwarding methods must return error, remote callback must not be called
    EXPECT_EQ(serviceCb->OnCaptureStarted(1, {1}), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiCaptureEndedInfo> endedInfos;
    EXPECT_EQ(serviceCb->OnCaptureEnded(1, endedInfos), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiCaptureErrorInfo> errorInfos;
    EXPECT_EQ(serviceCb->OnCaptureError(1, errorInfos), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    EXPECT_EQ(serviceCb->OnFrameShutter(1, {1}, 0), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);

    EXPECT_EQ(testCb->GetCallCount(), 0);
}

/**
 * @tc.name: NormalToDeath_Transition
 * @tc.desc: Callback alive → forwarding works; after OnCallbackDied → blocked.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(StreamCallbackDeathTest, NormalToDeath_Transition, TestSize.Level0)
{
    constexpr int32_t secondCaptureId = 2;
    auto testCb = sptr<TestStreamOperatorCallback>(new TestStreamOperatorCallback());

    auto serviceCb = sptr<StreamOperatorServiceCallback>(
        new StreamOperatorServiceCallback(testCb));

    // Alive: forwarding works
    EXPECT_EQ(serviceCb->OnCaptureStarted(1, {1}), 0);
    EXPECT_EQ(testCb->GetCallCount(), 1);

    // Simulate remote death
    serviceCb->OnCallbackDied();

    // Dead: blocked, no additional remote calls
    EXPECT_EQ(serviceCb->OnCaptureStarted(secondCaptureId, {1}), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    EXPECT_EQ(testCb->GetCallCount(), 1);
}

/**
 * @tc.name: NullCallbackAtConstruction_BlocksForwarding
 * @tc.desc: Verify that constructing StreamOperatorServiceCallback with nullptr
 *           causes all forwarding methods to return INVALID_ARGUMENT.
 *           No DeathRecipient is registered for null callbacks.
 *
 *           Regression target: if CHECK_IF_PTR_NULL_RETURN_VALUE guards
 *           are removed, this would crash on null dereference.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(StreamCallbackDeathTest, NullCallbackAtConstruction_BlocksForwarding, TestSize.Level1)
{
    auto serviceCb = sptr<StreamOperatorServiceCallback>(
        new StreamOperatorServiceCallback(nullptr));

    EXPECT_EQ(serviceCb->OnCaptureStarted(1, {1}), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiCaptureEndedInfo> endedInfos;
    EXPECT_EQ(serviceCb->OnCaptureEnded(1, endedInfos), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiCaptureErrorInfo> errorInfos;
    EXPECT_EQ(serviceCb->OnCaptureError(1, errorInfos), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    EXPECT_EQ(serviceCb->OnFrameShutter(1, {1}, 0), OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
}
