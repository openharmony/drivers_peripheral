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

#include <gtest/gtest.h>

#include "dcamera_host.h"
#include "dcamera_provider.h"
#include "dcamera_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DcameraProviderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

constexpr const char* TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";
const uint32_t ABILITYINFO_MAX_LENGTH = 50 * 1024 * 1024;

void DcameraProviderTest::SetUpTestCase(void)
{
}

void DcameraProviderTest::TearDownTestCase(void)
{
}

void DcameraProviderTest::SetUp(void)
{
}

void DcameraProviderTest::TearDown(void)
{
}

/**
 * @tc.name: GetAbilityInfo_001
 * @tc.desc: Verify GetAbilityInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, GetAbilityInfo_001, TestSize.Level1)
{
    std::string abilityInfo;
    std::string sinkAbilityInfo;
    std::string sourceCodecInfo;
    auto ret = DCameraProvider::GetInstance()->GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(ret, false);

    abilityInfo = "not a json object";
    ret = DCameraProvider::GetInstance()->GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(ret, false);

    abilityInfo = "{\"SourceCodec\": {}}";
    ret = DCameraProvider::GetInstance()->GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(ret, false);

    abilityInfo = "{\"SinkAbility\": \"not an object\", \"SourceCodec\": {}}";
    ret = DCameraProvider::GetInstance()->GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EnableDCameraDevice_001
 * @tc.desc: Verify EnableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, EnableDCameraDevice_001, TestSize.Level1)
{
    DHBase dhBase;
    std::string abilityInfo;
    sptr<IDCameraProviderCallback> callbackObj = nullptr;
    auto ret = DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callbackObj);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: EnableDCameraDevice_002
 * @tc.desc: Verify EnableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, EnableDCameraDevice_002, TestSize.Level1)
{
    DHBase dhBase;
    std::string abilityInfo;
    sptr<IDCameraProviderCallback> callbackObj = nullptr;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callbackObj);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: EnableDCameraDevice_003
 * @tc.desc: Verify EnableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, EnableDCameraDevice_003, TestSize.Level1)
{
    DHBase dhBase;
    std::string abilityInfo(ABILITYINFO_MAX_LENGTH + 1, 'a');
    sptr<IDCameraProviderCallback> callbackObj = nullptr;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callbackObj);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: EnableDCameraDevice_004
 * @tc.desc: Verify EnableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, EnableDCameraDevice_004, TestSize.Level1)
{
    DHBase dhBase;
    std::string abilityInfo = "abilityInfo";
    sptr<IDCameraProviderCallback> callbackObj = nullptr;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callbackObj);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: DisableDCameraDevice_001
 * @tc.desc: Verify DisableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, DisableDCameraDevice_001, TestSize.Level1)
{
    DHBase dhBase;
    auto ret = DCameraProvider::GetInstance()->DisableDCameraDevice(dhBase);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: DisableDCameraDevice_002
 * @tc.desc: Verify DisableDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, DisableDCameraDevice_002, TestSize.Level1)
{
    DHBase dhBase;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->DisableDCameraDevice(dhBase);
    EXPECT_NE(ret, DCamRetCode::DEVICE_NOT_INIT);
}

/**
 * @tc.name: AcquireBuffer_001
 * @tc.desc: Verify AcquireBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, AcquireBuffer_001, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 0;
    DCameraBuffer buffer;
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
    auto ret = DCameraProvider::GetInstance()->AcquireBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: AcquireBuffer_002
 * @tc.desc: Verify AcquireBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, AcquireBuffer_002, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = -1;
    DCameraBuffer buffer;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->AcquireBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: AcquireBuffer_003
 * @tc.desc: Verify AcquireBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, AcquireBuffer_003, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 1;
    DCameraBuffer buffer;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->AcquireBuffer(dhBase, streamId, buffer);
    EXPECT_NE(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: ShutterBuffer_001
 * @tc.desc: Verify ShutterBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ShutterBuffer_001, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 0;
    DCameraBuffer buffer;
    auto ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: ShutterBuffer_002
 * @tc.desc: Verify ShutterBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ShutterBuffer_002, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 0;
    DCameraBuffer buffer;
    buffer.index_ = -1;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    buffer.index_ = 1;
    buffer.size_ = -1;
    ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: ShutterBuffer_003
 * @tc.desc: Verify ShutterBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ShutterBuffer_003, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = -1;
    DCameraBuffer buffer;
    buffer.index_ = 1;
    buffer.size_ = 1;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    streamId = 1;
    ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: OnSettingsResult_001
 * @tc.desc: Verify OnSettingsResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, OnSettingsResult_001, TestSize.Level1)
{
    DHBase dhBase;
    DCameraSettings result;
    auto ret = DCameraProvider::GetInstance()->OnSettingsResult(dhBase, result);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: OnSettingsResult_002
 * @tc.desc: Verify OnSettingsResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, OnSettingsResult_002, TestSize.Level1)
{
    DHBase dhBase;
    DCameraSettings result;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->OnSettingsResult(dhBase, result);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: OnSettingsResult_003
 * @tc.desc: Verify OnSettingsResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, OnSettingsResult_003, TestSize.Level1)
{
    DHBase dhBase;
    DCameraSettings result;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    result.value_ = "value";
    auto ret = DCameraProvider::GetInstance()->OnSettingsResult(dhBase, result);
    EXPECT_NE(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: Notify_001
 * @tc.desc: Verify Notify
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, Notify_001, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHDFEvent event;
    auto ret = DCameraProvider::GetInstance()->Notify(dhBase, event);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: Notify_002
 * @tc.desc: Verify Notify
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, Notify_002, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHDFEvent event;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->Notify(dhBase, event);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: Notify_003
 * @tc.desc: Verify Notify
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, Notify_003, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHDFEvent event;
    std::string str(ABILITYINFO_MAX_LENGTH + 1, 'a');
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    event.content_ = str;
    auto ret = DCameraProvider::GetInstance()->Notify(dhBase, event);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: Notify_004
 * @tc.desc: Verify Notify
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, Notify_004, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHDFEvent event;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    event.content_ = "content";
    auto ret = DCameraProvider::GetInstance()->Notify(dhBase, event);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: RegisterCameraHdfListener_001
 * @tc.desc: Verify RegisterCameraHdfListener
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, RegisterCameraHdfListener_001, TestSize.Level1)
{
    sptr<IDCameraHdfCallback> callback = nullptr;
    EXPECT_EQ(DCamRetCode::INVALID_ARGUMENT,
        DCameraProvider::GetInstance()->RegisterCameraHdfListener(TEST_DEVICE_ID, callback));
}

/**
 * @tc.name: UnRegisterCameraHdfListener_001
 * @tc.desc: Verify UnRegisterCameraHdfListener
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, UnRegisterCameraHdfListener_001, TestSize.Level1)
{
    EXPECT_EQ(DCamRetCode::FAILED,
        DCameraProvider::GetInstance()->UnRegisterCameraHdfListener(TEST_DEVICE_ID));
}

/**
 * @tc.name: OpenSession_001
 * @tc.desc: Verify OpenSession
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, OpenSession_001, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
    auto ret = DCameraProvider::GetInstance()->OpenSession(dhBase);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: CloseSession_001
 * @tc.desc: Verify CloseSession
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, CloseSession_001, TestSize.Level1)
{
    DHBase dhBase;
    auto ret = DCameraProvider::GetInstance()->CloseSession(dhBase);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: ConfigureStreams_001
 * @tc.desc: Verify ConfigureStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ConfigureStreams_001, TestSize.Level1)
{
    DHBase dhBase;
    std::vector<DCStreamInfo> streamInfos;
    auto ret = DCameraProvider::GetInstance()->ConfigureStreams(dhBase, streamInfos);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: ReleaseStreams_001
 * @tc.desc: Verify ReleaseStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ReleaseStreams_001, TestSize.Level1)
{
    DHBase dhBase;
    std::vector<int> streamInfos;
    auto ret = DCameraProvider::GetInstance()->ReleaseStreams(dhBase, streamInfos);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: StartCapture_001
 * @tc.desc: Verify StartCapture
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, StartCapture_001, TestSize.Level1)
{
    DHBase dhBase;
    std::vector<DCCaptureInfo> streamInfos;
    auto ret = DCameraProvider::GetInstance()->StartCapture(dhBase, streamInfos);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: StopCapture_001
 * @tc.desc: Verify StopCapture
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, StopCapture_001, TestSize.Level1)
{
    DHBase dhBase;
    std::vector<int> streamInfos;
    auto ret = DCameraProvider::GetInstance()->StopCapture(dhBase, streamInfos);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: UpdateSettings_001
 * @tc.desc: Verify UpdateSettings
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, UpdateSettings_001, TestSize.Level1)
{
    DHBase dhBase;
    std::vector<DCameraSettings> settings;
    auto ret = DCameraProvider::GetInstance()->UpdateSettings(dhBase, settings);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetDCameraDevice_001
 * @tc.desc: Verify GetDCameraDevice
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, GetDCameraDevice_001, TestSize.Level1)
{
    DHBase dhBase;
    auto ret = DCameraProvider::GetInstance()->GetDCameraDevice(dhBase);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: AcquireBuffer_004
 * @tc.desc: Verify AcquireBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, AcquireBuffer_004, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 1;
    DCameraBuffer buffer;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";

    OHOS::sptr<DCameraDevice> dCamera(new (std::nothrow) DCameraDevice(dhBase, "sinkAbilityInfo",
        "sourceCodecInfo"));
    dCamera->dCameraStreamOperator_ = nullptr;
    std::string str = "deviceId__dhId";
    DCameraHost::GetInstance()->dCameraDeviceMap_[str] = dCamera;
    auto ret = DCameraProvider::GetInstance()->AcquireBuffer(dhBase, streamId, buffer);
    EXPECT_NE(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: ShutterBuffer_004
 * @tc.desc: Verify ShutterBuffer
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, ShutterBuffer_004, TestSize.Level1)
{
    DHBase dhBase;
    int32_t streamId = 1;
    DCameraBuffer buffer;
    buffer.index_ = 1;
    buffer.size_ = 1;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    auto ret = DCameraProvider::GetInstance()->ShutterBuffer(dhBase, streamId, buffer);
    EXPECT_EQ(ret, DCamRetCode::DEVICE_NOT_INIT);
}

/**
 * @tc.name: OnSettingsResult_004
 * @tc.desc: Verify OnSettingsResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, OnSettingsResult_004, TestSize.Level1)
{
    DHBase dhBase;
    DCameraSettings result;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    result.value_ = "value";
    auto ret = DCameraProvider::GetInstance()->OnSettingsResult(dhBase, result);
    EXPECT_NE(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: Notify_005
 * @tc.desc: Verify Notify
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, Notify_005, TestSize.Level1)
{
    DHBase dhBase;
    DCameraHDFEvent event;
    dhBase.deviceId_ = "deviceId";
    dhBase.dhId_ = "dhId";
    event.content_ = "content";
    auto ret = DCameraProvider::GetInstance()->Notify(dhBase, event);
    EXPECT_NE(ret, DCamRetCode::DEVICE_NOT_INIT);
}
}
}