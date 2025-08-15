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
#include "dcamera_test_utils.h"
#include "v1_0/icamera_device_callback.h"
#include "v1_0/icamera_host_callback.h"
#include "v1_2/icamera_host_callback.h"
#include "iremote_object.h"
#include "distributed_hardware_log.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DCameraHostTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

class MockCameraHostCallback : public HDI::Camera::V1_0::ICameraHostCallback {
public:
    MockCameraHostCallback() = default;
    ~MockCameraHostCallback() override = default;
    int32_t OnCameraStatus(const std::string &cameraId, CameraStatus status) override
    {
        return 0;
    }
    int32_t OnFlashlightStatus(const std::string &cameraId, FlashlightStatus status) override
    {
        return 0;
    }
    int32_t OnCameraEvent(const std::string &cameraId, CameraEvent event) override
    {
        return 0;
    }
};

class MockCameraHostCallbackV12 : public HDI::Camera::V1_2::ICameraHostCallback {
public:
    MockCameraHostCallbackV12() = default;
    ~MockCameraHostCallbackV12() override = default;
    int32_t OnCameraStatus(const std::string &cameraId, CameraStatus status) override
    {
        return 0;
    }
    int32_t OnFlashlightStatus(const std::string &cameraId, FlashlightStatus status) override
    {
        return 0;
    }
    int32_t OnCameraEvent(const std::string &cameraId, CameraEvent event) override
    {
        return 0;
    }
    int32_t OnFlashlightStatus_V1_2(FlashlightStatus status) override
    {
        return 0;
    }
};

class MockCameraDeviceCallback : public ICameraDeviceCallback {
public:
    MockCameraDeviceCallback() = default;
    ~MockCameraDeviceCallback() override = default;
    int32_t OnError(ErrorType type, int32_t errorCode) override
    {
        return 0;
    }
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t> &result) override
    {
        return 0;
    }
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject {u"MockIRemoteObject"}
    {
    }

    ~MockIRemoteObject()
    {
    }

    int32_t GetObjectRefCount()
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        return 0;
    }

    bool IsProxyObject() const
    {
        return true;
    }

    bool CheckObjectLegality() const
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface()
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args)
    {
        return 0;
    }
};

class MockDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject> &remote)
    {}
};

namespace {
constexpr const char* TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";
const uint32_t ID_MAX_SIZE = 2 * DEVID_MAX_LENGTH;
const uint32_t ABILITYINFO_MAX_LENGTH = 50 * 1024 * 1024;
const size_t MAX_DCAMERAS_NUMBER = 32;
}

void DCameraHostTest::SetUpTestCase(void)
{
}

void DCameraHostTest::TearDownTestCase(void)
{
}

void DCameraHostTest::SetUp(void)
{
}

void DCameraHostTest::TearDown(void)
{
}

/**
 * @tc.name: RegisterCameraHdfListener_001
 * @tc.desc: Verify RegisterCameraHdfListener
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraHostTest, RegisterCameraHdfListener_001, TestSize.Level1)
{
    sptr<IDCameraHdfCallback> callback = nullptr;
    EXPECT_EQ(DCamRetCode::INVALID_ARGUMENT,
        DCameraHost::GetInstance()->RegisterCameraHdfListener(TEST_DEVICE_ID, callback));
}

/**
 * @tc.name: UnRegisterCameraHdfListener_001
 * @tc.desc: Verify UnRegisterCameraHdfListener
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraHostTest, UnRegisterCameraHdfListener_001, TestSize.Level1)
{
    EXPECT_EQ(DCamRetCode::FAILED, DCameraHost::GetInstance()->UnRegisterCameraHdfListener(TEST_DEVICE_ID));
}

/**
 * @tc.name: SetCallback_001
 * @tc.desc: Verify SetCallback
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraHostTest, SetCallback_001, TestSize.Level1)
{
    sptr<HDI::Camera::V1_0::ICameraHostCallback> nullCallback = nullptr;
    int32_t ret = DCameraHost::GetInstance()->SetCallback(nullCallback);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);

    sptr<HDI::Camera::V1_2::ICameraHostCallback> callback = nullptr;
    ret = DCameraHost::GetInstance()->SetCallback_V1_2(callback);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SetCallback_002
 * @tc.desc: Verify SetCallback
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraHostTest, SetCallback_002, TestSize.Level1)
{
    sptr<HDI::Camera::V1_0::ICameraHostCallback> callback = sptr<MockCameraHostCallback>(
        new (std::nothrow) MockCameraHostCallback());
    int32_t ret = DCameraHost::GetInstance()->SetCallback(callback);
    EXPECT_EQ(ret, CamRetCode::NO_ERROR);

    sptr<HDI::Camera::V1_2::ICameraHostCallback> callbackV1_2 = sptr<MockCameraHostCallbackV12>(
        new (std::nothrow) MockCameraHostCallbackV12());
    ret = DCameraHost::GetInstance()->SetCallback_V1_2(callbackV1_2);
    EXPECT_EQ(ret, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: GetCameraIds_001
 * @tc.desc: Verify the GetCameraIds function when no camera devices.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, GetCameraIds_001, TestSize.Level1)
{
    std::vector<std::string> cameraIds;
    int32_t ret = DCameraHost::GetInstance()->GetCameraIds(cameraIds);
    EXPECT_EQ(ret, CamRetCode::NO_ERROR);
    EXPECT_TRUE(cameraIds.empty());
}

/**
 * @tc.name: GetCameraAbility_001
 * @tc.desc: Verify the GetCameraAbility function with invalid cameraId.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, GetCameraAbility_001, TestSize.Level1)
{
    std::string invalidCameraId = "";
    std::vector<uint8_t> cameraAbility;
    int32_t ret = DCameraHost::GetInstance()->GetCameraAbility(invalidCameraId, cameraAbility);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetCameraAbility_002
 * @tc.desc: Verify the GetCameraAbility function with non-existent cameraId.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, GetCameraAbility_002, TestSize.Level1)
{
    std::string nonExistentCameraId = "non_existent_camera_id";
    std::vector<uint8_t> cameraAbility;
    int32_t ret = DCameraHost::GetInstance()->GetCameraAbility(nonExistentCameraId, cameraAbility);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: OpenCamera_001
 * @tc.desc: Verify the OpenCamera function with invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, OpenCamera_001, TestSize.Level1)
{
    std::string invalidCameraId = "";
    sptr<HDI::Camera::V1_0::ICameraDeviceCallback> nullCallback = nullptr;
    sptr<HDI::Camera::V1_0::ICameraDevice> device = nullptr;

    int32_t ret = DCameraHost::GetInstance()->OpenCamera(invalidCameraId, nullCallback, device);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: OpenCamera_002
 * @tc.desc: Verify the OpenCamera function with non-existent camera.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, OpenCamera_002, TestSize.Level1)
{
    std::string nonExistentCameraId = "non_existent_camera";
    sptr<MockCameraDeviceCallback> mockCallback = sptr<MockCameraDeviceCallback>(
        new (std::nothrow) MockCameraDeviceCallback());
    sptr<HDI::Camera::V1_0::ICameraDevice> device = nullptr;

    int32_t ret = DCameraHost::GetInstance()->OpenCamera(nonExistentCameraId, mockCallback, device);
    EXPECT_EQ(ret, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: AddDCameraDevice_001
 * @tc.desc: Verify the AddDCameraDevice function with invalid DHBase.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDCameraDevice_001, TestSize.Level1)
{
    DHBase invalidDhBase = { "test001", "test001" };
    std::string sinkAbilityInfo = "test_sink_info";
    std::string sourceCodecInfo = "test_codec_info";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;

    DCamRetCode ret = DCameraHost::GetInstance()->AddDCameraDevice(invalidDhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    std::vector<std::string> cameraIds;
    int32_t val = DCameraHost::GetInstance()->GetCameraIds(cameraIds);
    EXPECT_EQ(val, CamRetCode::NO_ERROR);

    std::string cameraId = "test001__test001";
    std::vector<uint8_t> cameraAbility;
    val = DCameraHost::GetInstance()->GetCameraAbility(cameraId, cameraAbility);
    EXPECT_EQ(val, CamRetCode::INVALID_ARGUMENT);

    sptr<MockCameraDeviceCallback> mockCallback = sptr<MockCameraDeviceCallback>(
        new (std::nothrow) MockCameraDeviceCallback());
    sptr<HDI::Camera::V1_0::ICameraDevice> device = nullptr;

    val = DCameraHost::GetInstance()->OpenCamera(cameraId, mockCallback, device);
    EXPECT_EQ(val, CamRetCode::INVALID_ARGUMENT);

    ret = DCameraHost::GetInstance()->RemoveDCameraDevice(invalidDhBase);
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: AddDCameraDevice_002
 * @tc.desc: Verify the AddDCameraDevice function with empty sinkAbilityInfo.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDCameraDevice_002, TestSize.Level1)
{
    DHBase dhBase = { "test_dev_id", "test_dh_id" };
    std::string emptySinkAbilityInfo = "";
    std::string sourceCodecInfo = "test_codec_info";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;

    DCamRetCode ret = DCameraHost::GetInstance()->AddDCameraDevice(dhBase, emptySinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: RemoveDCameraDevice_001
 * @tc.desc: Verify the RemoveDCameraDevice function with invalid DHBase.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, RemoveDCameraDevice_001, TestSize.Level1)
{
    DHBase invalidDhBase = { "", "" };
    DCamRetCode ret = DCameraHost::GetInstance()->RemoveDCameraDevice(invalidDhBase);
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: IsCameraIdInvalid_001
 * @tc.desc: Verify the IsCameraIdInvalid function with empty cameraId.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, IsCameraIdInvalid_001, TestSize.Level1)
{
    std::string emptyCameraId = "";
    bool ret = DCameraHost::GetInstance()->IsCameraIdInvalid(emptyCameraId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsCameraIdInvalid_002
 * @tc.desc: Verify the IsCameraIdInvalid function with too long cameraId.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, IsCameraIdInvalid_002, TestSize.Level1)
{
    std::string longCameraId(ID_MAX_SIZE + 1, 'a');
    bool ret = DCameraHost::GetInstance()->IsCameraIdInvalid(longCameraId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UnsupportedMethods_001
 * @tc.desc: Verify unsupported methods return METHOD_NOT_SUPPORTED.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, UnsupportedMethods_001, TestSize.Level1)
{
    std::string cameraId = "camera_001";
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost resourceCost;
    int32_t  ret = DCameraHost::GetInstance()->GetResourceCost(cameraId, resourceCost);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    ret = DCameraHost::GetInstance()->NotifyDeviceStateChangeInfo(0, 0);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    ret = DCameraHost::GetInstance()->SetFlashlight("test_camera", true);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    ret = DCameraHost::GetInstance()->SetFlashlight_V1_2(0.0f);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    ret = DCameraHost::GetInstance()->PreCameraSwitch("test_camera");
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    PrelaunchConfig config;
    ret = DCameraHost::GetInstance()->PrelaunchWithOpMode(config, 0);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);

    ret = DCameraHost::GetInstance()->Prelaunch(config);
    EXPECT_EQ(ret, CamRetCode::METHOD_NOT_SUPPORTED);
}

/**
 * @tc.name: AddDeviceParamCheck_001
 * @tc.desc: Verify AddDeviceParamCheck.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDeviceParamCheck_001, TestSize.Level1)
{
    DHBase dhBase = { "", "" };
    std::string sinkAbilityInfo = "test_sink_info";
    std::string sourceCodecInfo = "test_codec_info";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;
    DCamRetCode ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: AddDeviceParamCheck_002
 * @tc.desc: Verify AddDeviceParamCheck.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDeviceParamCheck_002, TestSize.Level1)
{
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    std::string sinkAbilityInfo = "";
    std::string sourceCodecInfo = "";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;
    DCamRetCode ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    std::string longSinkInfo(ABILITYINFO_MAX_LENGTH + 1, 'a');
    ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, longSinkInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    sinkAbilityInfo = "test_sink_info";
    ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    std::string longCodecInfo(ABILITYINFO_MAX_LENGTH + 1, 'a');
    ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        longCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: AddDeviceParamCheck_003
 * @tc.desc: Verify AddDeviceParamCheck.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDeviceParamCheck_003, TestSize.Level1)
{
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    std::string sinkAbilityInfo = "test_sink_info";
    std::string sourceCodecInfo = "test_codec_info";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;
    for (size_t i = 0; i < MAX_DCAMERAS_NUMBER + 1; ++i) {
        DCameraHost::GetInstance()->dCameraDeviceMap_["camera" + std::to_string(i)] = nullptr;
    }
    DCamRetCode ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
}

/**
 * @tc.name: AddDeviceParamCheck_004
 * @tc.desc: Verify AddDeviceParamCheck.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddDeviceParamCheck_004, TestSize.Level1)
{
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    std::string sinkAbilityInfo = "test_sink_info";
    std::string sourceCodecInfo = "test_codec_info";
    sptr<IDCameraProviderCallback> nullCallback = nullptr;
    DCamRetCode ret = DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo,
        sourceCodecInfo, nullCallback);
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);

    DCameraHost::GetInstance()->NotifyDCameraStatus(dhBase, 0);
}

/**
 * @tc.name: AddClearRegisterRecipient_001
 * @tc.desc: Verify AddClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddClearRegisterRecipient_001, TestSize.Level1)
{
    DHLOGI("AddClearRegisterRecipient_001");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = nullptr;
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: AddClearRegisterRecipient_002
 * @tc.desc: Verify AddClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddClearRegisterRecipient_002, TestSize.Level1)
{
    DHLOGI("AddClearRegisterRecipient_002");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: AddClearRegisterRecipient_003
 * @tc.desc: Verify AddClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, AddClearRegisterRecipient_003, TestSize.Level1)
{
    DHLOGI("AddClearRegisterRecipient_003");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: RemoveClearRegisterRecipient_001
 * @tc.desc: Verify RemoveClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, RemoveClearRegisterRecipient_001, TestSize.Level1)
{
    DHLOGI("RemoveClearRegisterRecipient_001");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);

    remote = nullptr;
    result = DCameraHost::GetInstance()->RemoveClearRegisterRecipient(remote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: RemoveClearRegisterRecipient_002
 * @tc.desc: Verify RemoveClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, RemoveClearRegisterRecipient_002, TestSize.Level1)
{
    DHLOGI("RemoveClearRegisterRecipient_002");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);

    sptr<IRemoteObject> nullRemote = nullptr;
    result = DCameraHost::GetInstance()->RemoveClearRegisterRecipient(nullRemote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: RemoveClearRegisterRecipient_003
 * @tc.desc: Verify RemoveClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, RemoveClearRegisterRecipient_003, TestSize.Level1)
{
    DHLOGI("RemoveClearRegisterRecipient_003");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);

    result = DCameraHost::GetInstance()->RemoveClearRegisterRecipient(remote, dhBase);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: RemoveClearRegisterRecipient_004
 * @tc.desc: Verify RemoveClearRegisterRecipient.
 * @tc.type: FUNC
 */
HWTEST_F(DCameraHostTest, RemoveClearRegisterRecipient_004, TestSize.Level1)
{
    DHLOGI("RemoveClearRegisterRecipient_004");
    DHBase dhBase = { "test_device_id", "test_dh_id" };
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    ASSERT_NE(remote, nullptr);
    int32_t result = DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);

    DHBase dhBase2 = { "device_id", "dh_id" };
    result = DCameraHost::GetInstance()->RemoveClearRegisterRecipient(remote, dhBase2);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}
}
}