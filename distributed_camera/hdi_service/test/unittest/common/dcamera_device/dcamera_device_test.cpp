/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "dcamera_device.h"
#include "constants.h" // For METADATA_CAPACITY_MAX_SIZE
#include "mock_dcamera_provider.h"
#include "mock_icamera_device_callback.h"
#include "mock_dstream_operator_callback.h"
#include "v1_3/istream_operator_callback.h" // For IStreamOperatorCallback
#include "mock_dcamera_provider_callback.h"
#include "dcamera_host.h"
#include "v1_3/types.h"
#include "metadata_utils.h"
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

std::string g_providerMockRet;

class DCameraDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    void OpenDeviceSuccessfully();

    sptr<DCameraDevice> dcameraDevice_ = nullptr;
    sptr<MockDCameraProvider> mockProvider_ = nullptr;
};

constexpr const char* TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";
constexpr const char* TEST_CAMERA_DH_ID_0 = "camera_0";
constexpr const char* TEST_ABILITY = R"({"CodecType": ["avenc_mpeg4"], "Position": "BACK"})";

std::shared_ptr<DCameraHDFEvent> CreateHDFEvent(DCameraEventResult result)
{
    auto event = std::make_shared<DCameraHDFEvent>();
    event->type_ = DCameraEventType::DCAMERA_MESSAGE;
    event->result_ = result;
    return event;
}

void DCameraDeviceTest::SetUpTestCase(void)
{
}

void DCameraDeviceTest::TearDownTestCase(void)
{
}

void DCameraDeviceTest::SetUp(void)
{
    mockProvider_ = new MockDCameraProvider();
    MockDCameraProvider::SetInstance(mockProvider_);

    DHBase dhBase = {TEST_DEVICE_ID, TEST_CAMERA_DH_ID_0};
    dcameraDevice_ = sptr<DCameraDevice>(new (std::nothrow) DCameraDevice(dhBase, TEST_ABILITY, TEST_ABILITY));
    dcameraDevice_ = new DCameraDevice(dhBase, TEST_ABILITY, TEST_ABILITY);

    sptr<IDCameraProviderCallback> providerCallback = new MockDCameraProviderCallback();
    dcameraDevice_->SetProviderCallback(providerCallback);

    std::string cameraId = std::string(TEST_DEVICE_ID) + "__" + std::string(TEST_CAMERA_DH_ID_0);
    DCameraHost::GetInstance()->dCameraDeviceMap_[cameraId] = dcameraDevice_;

    g_providerMockRet = "";
}

void DCameraDeviceTest::TearDown(void)
{
    if (dcameraDevice_ != nullptr) {
        if (dcameraDevice_->IsOpened()) {
            dcameraDevice_->Close();
        }
    }
    dcameraDevice_ = nullptr;
    mockProvider_ = nullptr;
    MockDCameraProvider::SetInstance(nullptr);
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
}

void DCameraDeviceTest::OpenDeviceSuccessfully()
{
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();

    const std::chrono::milliseconds sleepDuration(100);
    std::thread notifyThread([this, &sleepDuration]() {
        std::this_thread::sleep_for(sleepDuration);
        dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_CHANNEL_CONNECTED));
    });

    CamRetCode rc = dcameraDevice_->OpenDCamera(callback);
    notifyThread.join();

    ASSERT_EQ(rc, CamRetCode::NO_ERROR);
    ASSERT_TRUE(dcameraDevice_->IsOpened());
}

/**
 * @tc.name: dcamera_device_test_001
 * @tc.desc: Verify SetResultMode success
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_001, TestSize.Level0)
{
    ASSERT_NE(dcameraDevice_, nullptr);

    ResultCallbackMode mode = PER_FRAME;
    int32_t rc = dcameraDevice_->SetResultMode(mode);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_002
 * @tc.desc: Verify GetEnabledResults success
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_002, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);

    std::vector<int32_t> results;
    int32_t rc = dcameraDevice_->GetEnabledResults(results);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_003
 * @tc.desc: Verify SetResultMode ON_CHANGED
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_003, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    sptr<HDI::Camera::V1_3::IStreamOperator> streamOperator;
    int32_t rc = dcameraDevice_->GetStreamOperator_V1_3(nullptr, streamOperator);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_004
 * @tc.desc: Verify GetDCameraAbility
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_004, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    CamRetCode rc = dcameraDevice_->OpenDCamera(nullptr);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_005
 * @tc.desc: Verify GetDCameraAbility
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_005, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();
    g_providerMockRet = "OpenSession_Fail";
    CamRetCode rc = dcameraDevice_->OpenDCamera(callback);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
    EXPECT_FALSE(dcameraDevice_->IsOpened());
}

/**
 * @tc.name: dcamera_device_test_006
 * @tc.desc: Verify OpenDCamera success case
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_006, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    OpenDeviceSuccessfully();
}

/**
 * @tc.name: dcamera_device_test_007
 * @tc.desc: Verify UpdateSettings when device is not opened
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_007, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    std::vector<uint8_t> settings;
    settings.push_back(1);
    dcameraDevice_->isOpened_ = false;
    int32_t rc = dcameraDevice_->UpdateSettings(settings);
    EXPECT_EQ(rc, CamRetCode::CAMERA_CLOSED);
}

/**
 * @tc.name: dcamera_device_test_008
 * @tc.desc: Verify UpdateSettings when provider fails
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_008, TestSize.Level1)
{
    // Setup
    OpenDeviceSuccessfully();

    // Test
    g_providerMockRet = "UpdateSettings_Fail";
    std::vector<uint8_t> settings;
    settings.push_back(1);
    dcameraDevice_->isOpened_ = true;
    int32_t rc = dcameraDevice_->UpdateSettings(settings);

    // Verify
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_009
 * @tc.desc: Verify Notify with DCAMERA_EVENT_CHANNEL_DISCONNECTED event
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_009, TestSize.Level1)
{
    // Setup
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();
    dcameraDevice_->OpenDCamera(callback);
    dcameraDevice_->Close();
    dcameraDevice_->isOpened_ = true;
    dcameraDevice_->OpenDCamera(callback);
    ASSERT_TRUE(dcameraDevice_->IsOpened());

    // Test
    dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_CHANNEL_DISCONNECTED));

    // Verify
    EXPECT_EQ(callback->GetCallCount(), 1);
    EXPECT_EQ(callback->GetLastErrorType(), ErrorType::DEVICE_DISCONNECT);
    EXPECT_FALSE(dcameraDevice_->IsOpened());
}

/**
 * @tc.name: dcamera_device_test_010
 * @tc.desc: Verify Close function
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_010, TestSize.Level1)
{
    // Setup
    OpenDeviceSuccessfully();
    ASSERT_TRUE(dcameraDevice_->IsOpened());

    // Test
    int32_t rc = dcameraDevice_->Close();

    // Verify
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_FALSE(dcameraDevice_->IsOpened());
}

/**
 * @tc.name: dcamera_device_test_011
 * @tc.desc: Verify OnSettingsResult with null input
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_011, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    DCamRetCode ret = dcameraDevice_->OnSettingsResult(nullptr);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_012
 * @tc.desc: Verify EnableResult with invalid argument
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_012, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    std::vector<int32_t> emptyResults;
    int32_t ret = dcameraDevice_->EnableResult(emptyResults);
    EXPECT_EQ(ret, CamRetCode::DEVICE_ERROR);
}

/**
 * @tc.name: dcamera_device_test_013
 * @tc.desc: Verify UpdateSettings with empty settings vector
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_013, TestSize.Level1)
{
    OpenDeviceSuccessfully();

    std::vector<uint8_t> emptySettings;
    int32_t rc = dcameraDevice_->UpdateSettings(emptySettings);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_014
 * @tc.desc: Verify UpdateSettings with oversized settings vector
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_014, TestSize.Level1)
{
    OpenDeviceSuccessfully();
    std::vector<uint8_t> oversizedSettings(METADATA_CAPACITY_MAX_SIZE + 1, 0);
    int32_t rc = dcameraDevice_->UpdateSettings(oversizedSettings);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_015
 * @tc.desc: Verify Notify with all other event types
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_015, TestSize.Level1)
{
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();
    dcameraDevice_->OpenDCamera(callback);
    dcameraDevice_->isOpened_ = true;
    callback->Reset();
    dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_OPEN_CHANNEL_ERROR));
    EXPECT_EQ(callback->GetCallCount(), 0);

    callback->Reset();
    dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_CONFIG_STREAMS_ERROR));
    EXPECT_EQ(callback->GetLastErrorType(), ErrorType::REQUEST_TIMEOUT);

    callback->Reset();
    dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_START_CAPTURE_ERROR));
    EXPECT_EQ(callback->GetLastErrorType(), ErrorType::REQUEST_TIMEOUT);
    callback->Reset();
    dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_DEVICE_ERROR));
    EXPECT_EQ(callback->GetLastErrorType(), ErrorType::DRIVER_ERROR);

    callback->Reset();
    auto ret = dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_DEVICE_PREEMPT));
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_FALSE(dcameraDevice_->IsOpened());

    dcameraDevice_->isOpened_ = true;

    callback->Reset();
    ret = dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_DEVICE_IN_USE));
    EXPECT_EQ(ret, SUCCESS);
    
    callback->Reset();
    ret = dcameraDevice_->Notify(CreateHDFEvent(DCameraEventResult::DCAMERA_EVENT_NO_PERMISSION));
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: dcamera_device_test_016
 * @tc.desc: Verify Notify and OnSettingsResult with invalid arguments
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_016, TestSize.Level1)
{
    DCamRetCode rcNotify = dcameraDevice_->Notify(nullptr);
    EXPECT_EQ(rcNotify, DCamRetCode::INVALID_ARGUMENT);

    auto event = std::make_shared<DCameraHDFEvent>();
    event->type_ = static_cast<DCameraEventType>(99);
    rcNotify = dcameraDevice_->Notify(event);
    EXPECT_EQ(rcNotify, DCamRetCode::INVALID_ARGUMENT);

    auto settings = std::make_shared<DCameraSettings>();
    settings->type_ = static_cast<DCSettingsType>(99);
    settings->value_ = "some_value";
    DCamRetCode rcSettings = dcameraDevice_->OnSettingsResult(settings);
    EXPECT_EQ(rcSettings, DCamRetCode::INVALID_ARGUMENT);


    settings->type_ = DCSettingsType::METADATA_RESULT;
    settings->value_ = "";
    rcSettings = dcameraDevice_->OnSettingsResult(settings);
    EXPECT_EQ(rcSettings, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_device_test_017
 * @tc.desc: Verify OpenDCamera timeout
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_017, TestSize.Level2)
{
    // This test simulates a timeout by not sending the connected event.
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();
    CamRetCode rc = dcameraDevice_->OpenDCamera(callback);
    EXPECT_EQ(rc, CamRetCode::DEVICE_ERROR);
}
/**
 * @tc.name: dcamera_device_test_018
 * @tc.desc: Verify GetStreamOperator fails when stream operator is null
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_018, TestSize.Level1)
{
    OHOS::sptr<HDI::Camera::V1_0::IStreamOperatorCallback> callback(new (std::nothrow) MockDStreamOperatorCallback());
    sptr<HDI::Camera::V1_0::IStreamOperator> streamOperator;
    dcameraDevice_->dCameraStreamOperator_ = nullptr;
    int32_t rc = dcameraDevice_->GetStreamOperator(callback, streamOperator);
    EXPECT_EQ(rc, CamRetCode::DEVICE_ERROR);
}

/**
 * @tc.name: dcamera_device_test_019
 * @tc.desc: Verify metadata-related functions fail when metadata processor is null
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_019, TestSize.Level1)
{
    dcameraDevice_->dMetadataProcessor_ = nullptr;
    ResultCallbackMode mode = PER_FRAME;
    int32_t re = dcameraDevice_->SetResultMode(mode);
    EXPECT_EQ(re, CamRetCode::DEVICE_ERROR);

    std::vector<int32_t> results;
    re = dcameraDevice_->GetEnabledResults(results);
    EXPECT_EQ(re, CamRetCode::DEVICE_ERROR);

    std::shared_ptr<CameraAbility> ability = nullptr;
    std::string sinkAbility = "sink";
    dcameraDevice_->SetDcameraAbility(sinkAbility);
    CamRetCode rc = dcameraDevice_->GetDCameraAbility(ability);
    EXPECT_EQ(true, rc == CamRetCode::INVALID_ARGUMENT);

    dcameraDevice_->SetDcameraAbility(TEST_ABILITY);
    rc = dcameraDevice_->GetDCameraAbility(ability);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
    results.push_back(1);
    int32_t result = dcameraDevice_->EnableResult(results);
    EXPECT_EQ(result, CamRetCode::DEVICE_ERROR);
    result = dcameraDevice_->DisableResult(results);
    EXPECT_EQ(result, CamRetCode::DEVICE_ERROR);

    auto settingsResult = std::make_shared<DCameraSettings>();
    settingsResult->type_ = DCSettingsType::METADATA_RESULT;
    settingsResult->value_ = "some_value";
    DCamRetCode ret = dcameraDevice_->OnSettingsResult(settingsResult);
    EXPECT_EQ(ret, DCamRetCode::DEVICE_NOT_INIT);
}

/**
 * @tc.name: dcamera_device_test_020
 * @tc.desc: Verify OpenDCamera fails when DCameraProvider is null
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_020, TestSize.Level1)
{
    MockDCameraProvider::SetInstance(nullptr);
    sptr<HDI::Camera::V1_0::MockCameraDeviceCallback> callback = new HDI::Camera::V1_0::MockCameraDeviceCallback();
    CamRetCode rc = dcameraDevice_->OpenDCamera(callback);
    EXPECT_EQ(rc, CamRetCode::DEVICE_ERROR);
}

/**
 * @tc.name: dcamera_device_test_021
 * @tc.desc: Verify Close fails when DCameraProvider is null
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_021, TestSize.Level1)
{
    OpenDeviceSuccessfully();
    MockDCameraProvider::SetInstance(nullptr);
    int32_t rc = dcameraDevice_->Close();
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_022
 * @tc.desc: Verify DisableResult with invalid oversized vector
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_022, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    std::vector<int32_t> oversizedResults(METADATA_CAPACITY_MAX_SIZE + 1, 0);
    int32_t ret = dcameraDevice_->DisableResult(oversizedResults);
    EXPECT_EQ(ret, CamRetCode::DEVICE_ERROR);
}

/**
 * @tc.name: dcamera_device_test_023
 * @tc.desc: Verify UpdateSettings when system switch
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_023, TestSize.Level1)
{
    ASSERT_NE(dcameraDevice_, nullptr);
    std::vector<uint8_t> settings;
    auto metaData = make_shared<OHOS::Camera::CameraMetadata>(100, 200);
    int8_t cameraType[] = {10, 30};
    int32_t cameraFpsRange[] = {10, 30};
    uint32_t cameraMesureExposureTime[] = {10};
    int64_t sensorExposeTime[] = {30};
    float sensorInfoPhysicalSize[] = {0.1};
    float jpegGpsCoordinates[] = {0.1, 0.1};
    bool switchFlag[] = {true};
    int32_t rotate[] = {90};

    camera_rational_t controlAeCompenstationStep[] = {{1, 3}};
    metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 1);
    metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 2);
    metaData->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, cameraMesureExposureTime, 1);
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, sensorExposeTime, 1);
    metaData->addEntry(OHOS_SENSOR_INFO_PHYSICAL_SIZE, sensorInfoPhysicalSize, 1);
    metaData->addEntry(OHOS_JPEG_GPS_COORDINATES, jpegGpsCoordinates, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP + 1, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP + 2, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP + 3, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP + 4, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP + 5, controlAeCompenstationStep, 1);
    metaData->addEntry(OHOS_CONTROL_REQUEST_CAMERA_SWITCH, switchFlag, 1);
    metaData->addEntry(OHOS_CONTROL_CAMERA_SWITCH_INFOS, rotate, 1);
    dcameraDevice_->isOpened_ = true;
    bool ret = OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metaData, settings);
    if (!ret) {
        EXPECT_EQ(ret, CamRetCode::NO_ERROR);
        return;
    }
    int32_t rc = dcameraDevice_->UpdateSettings(settings);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    switchFlag[0] = false;
    metaData->updateEntry(OHOS_CONTROL_REQUEST_CAMERA_SWITCH, switchFlag, 1);

    rc = dcameraDevice_->UpdateSettings(settings);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}
}
}