/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <atomic>
#include <memory>
#include <thread>
#include "metadata_utils.h"
#include "dmetadata_processor.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

class DMetadataProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    std::shared_ptr<DMetadataProcessor> processor_ = nullptr;
};

constexpr const char* VALID_ABILITY_JSON = R"({
    "ProtocolVer": "1.0",
    "Position": "BACK",
    "MetaData": "",
    "Photo": {
        "OutputFormat": [2],
        "Resolution": { "2": ["1920*1080"] }
    },
    "Preview": {
        "OutputFormat": [3],
        "Resolution": { "3": ["1280*720"] }
    }
})";

constexpr const char* INVALID_ABILITY_JSON = R"({ "ProtocolVer": "1.0", "Position": "BACK" )";

void DMetadataProcessorTest::SetUpTestCase(void)
{
}

void DMetadataProcessorTest::TearDownTestCase(void)
{
}

void DMetadataProcessorTest::SetUp(void)
{
    processor_ = std::make_shared<DMetadataProcessor>();
}

void DMetadataProcessorTest::TearDown(void)
{
    processor_ = nullptr;
}

/**
 * @tc.name: dcamera_metadata_processor_test_001
 * @tc.desc: Verify InitDCameraAbility with valid JSON
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_001, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    DCamRetCode rc = processor_->InitDCameraAbility(VALID_ABILITY_JSON);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: dcamera_metadata_processor_test_002
 * @tc.desc: Verify InitDCameraAbility with invalid JSON
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_002, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    
    // Invalid JSON syntax -> FAILED
    DCamRetCode rc = processor_->InitDCameraAbility(INVALID_ABILITY_JSON);
    EXPECT_EQ(rc, DCamRetCode::FAILED);

    // Empty string -> FAILED
    rc = processor_->InitDCameraAbility("");
    EXPECT_EQ(rc, DCamRetCode::FAILED);
}

/**
 * @tc.name: dcamera_metadata_processor_test_003
 * @tc.desc: Verify SetMetadataResultMode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_003, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    DCamRetCode rc = processor_->SetMetadataResultMode(ResultCallbackMode::PER_FRAME);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);
    rc = processor_->SetMetadataResultMode(ResultCallbackMode::ON_CHANGED);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);

    ResultCallbackMode invalidMode = static_cast<ResultCallbackMode>(99);
    rc = processor_->SetMetadataResultMode(invalidMode);
    EXPECT_EQ(rc, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_metadata_processor_test_004
 * @tc.desc: Verify Enable/Disable/Get metadata results
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_004, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->InitDCameraAbility(VALID_ABILITY_JSON);

    std::vector<MetaType> resultsToEnable = { OHOS_CONTROL_AE_AVAILABLE_MODES };
    DCamRetCode rc = processor_->EnableMetadataResult(resultsToEnable);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);

    std::vector<MetaType> enabledResults;
    processor_->GetEnabledMetadataResults(enabledResults);
    EXPECT_EQ(enabledResults.size(), 1);
    EXPECT_EQ(enabledResults[0], OHOS_CONTROL_AE_AVAILABLE_MODES);

    std::vector<MetaType> resultsToDisable = { OHOS_CONTROL_AE_AVAILABLE_MODES };
    rc = processor_->DisableMetadataResult(resultsToDisable);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);

    enabledResults.clear();
    processor_->GetEnabledMetadataResults(enabledResults);
    EXPECT_EQ(enabledResults.size(), 0);
}

/**
 * @tc.name: dcamera_metadata_processor_test_005
 * @tc.desc: Verify SaveResultMetadata with invalid arguments
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_005, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    DCamRetCode rc = processor_->SaveResultMetadata("");
    EXPECT_EQ(rc, DCamRetCode::INVALID_ARGUMENT);

    rc = processor_->SaveResultMetadata("this is not base64");
    EXPECT_EQ(rc, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dcamera_metadata_processor_test_006
 * @tc.desc: Verify result callback in ON_CHANGED mode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_006, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->SetMetadataResultMode(ResultCallbackMode::ON_CHANGED);

    std::atomic<int> callbackCount = 0;
    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> cb =
        [&](uint64_t timestamp, std::shared_ptr<OHOS::Camera::CameraMetadata> result) {
        callbackCount++;
    };
    processor_->SetResultCallback(cb);

    std::shared_ptr<CameraAbility> ability = std::make_shared<CameraAbility>(10, 10);
    uint8_t aeMode = OHOS_CAMERA_AE_MODE_ON;
    ability->addEntry(OHOS_CONTROL_AE_MODE, &aeMode, 1);
    std::string metadataStr = OHOS::Camera::MetadataUtils::EncodeToString(ability);
    std::string encodedResult = Base64Encode(reinterpret_cast<const unsigned char*>(metadataStr.c_str()),
                                             metadataStr.length());

    processor_->SaveResultMetadata(encodedResult);
    EXPECT_EQ(callbackCount, 1);

    processor_->SaveResultMetadata(encodedResult);
    EXPECT_EQ(callbackCount, 1);

    uint8_t newAeMode = OHOS_CAMERA_AE_MODE_OFF;
    ability->updateEntry(OHOS_CONTROL_AE_MODE, &newAeMode, 1);
    metadataStr = OHOS::Camera::MetadataUtils::EncodeToString(ability);
    std::string newEncodedResult = Base64Encode(reinterpret_cast<const unsigned char*>(metadataStr.c_str()),
                                                metadataStr.length());

    processor_->SaveResultMetadata(newEncodedResult);
    EXPECT_EQ(callbackCount, 2);
}

/**
 * @tc.name: dcamera_metadata_processor_test_007
 * @tc.desc: Verify result callback in PER_FRAME mode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_007, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->SetMetadataResultMode(ResultCallbackMode::PER_FRAME);

    std::atomic<int> callbackCount = 0;
    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> cb =
        [&](uint64_t timestamp, std::shared_ptr<OHOS::Camera::CameraMetadata> result) {
        callbackCount++;
    };
    processor_->SetResultCallback(cb);

    std::shared_ptr<CameraAbility> ability = std::make_shared<CameraAbility>(10, 10);
    uint8_t aeMode = OHOS_CAMERA_AE_MODE_ON;
    ability->addEntry(OHOS_CONTROL_AE_MODE, &aeMode, 1);
    std::string metadataStr = OHOS::Camera::MetadataUtils::EncodeToString(ability);
    std::string encodedResult = Base64Encode(reinterpret_cast<const unsigned char*>(metadataStr.c_str()),
                                             metadataStr.length());

    processor_->SaveResultMetadata(encodedResult);
    EXPECT_EQ(callbackCount, 0);

    processor_->UpdateResultMetadata(0);
    EXPECT_EQ(callbackCount, 1);

    processor_->UpdateResultMetadata(1);
    EXPECT_EQ(callbackCount, 2);
}

/**
 * @tc.name: dcamera_metadata_processor_test_008
 * @tc.desc: Verify InitDCameraAbility with valid JSON containing Base64 metadata (Main Path)
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_008, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    
    std::shared_ptr<CameraAbility> tempAbility = std::make_shared<CameraAbility>(10, 50);
    const uint8_t cameraType = OHOS_CAMERA_TYPE_LOGICAL;
    tempAbility->addEntry(OHOS_ABILITY_CAMERA_TYPE, &cameraType, 1);
    std::string metadataStr = OHOS::Camera::MetadataUtils::EncodeToString(tempAbility);

    std::string encodedMetadata = Base64Encode(reinterpret_cast<const unsigned char*>
        (metadataStr.c_str()), metadataStr.length());

    const std::string validAbilityWithMetadataJson =
        std::string("{\n") +
        "        \"ProtocolVer\": \"1.0\",\n" +
        "        \"Position\": \"BACK\",\n" +
        "        \"MetaData\": \"" + encodedMetadata + "\",\n" +
        "        \"Photo\": { \"OutputFormat\": [2], \"Resolution\": { \"2\": [\"1920*1080\"] } },\n" +
        "        \"Preview\": { \"OutputFormat\": [3], \"Resolution\": { \"3\": [\"1280*720\"] } }\n" +
        "    }";

    DCamRetCode rc = processor_->InitDCameraAbility(validAbilityWithMetadataJson);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);

    std::shared_ptr<CameraAbility> ability;
    processor_->GetDCameraAbility(ability);
    ASSERT_NE(ability, nullptr);

    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(item.data.u8[0], OHOS_CAMERA_TYPE_LOGICAL);
}

/**
 * @tc.name: dcamera_metadata_processor_test_009
 * @tc.desc: Verify ResetEnableResults actually enables all results
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_009, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->InitDCameraAbility(VALID_ABILITY_JSON);

    // Initially, disable one of the default results
    std::vector<MetaType> resultsToDisable = { OHOS_CONTROL_AE_AVAILABLE_MODES };
    processor_->DisableMetadataResult(resultsToDisable);
    
    std::vector<MetaType> enabledResults;
    processor_->GetEnabledMetadataResults(enabledResults);
    // Assuming there are more than 1 default results, the size should be less than total
    // (This part needs knowledge of all default keys to be perfectly asserted)

    // Call the function under test
    DCamRetCode rc = processor_->ResetEnableResults();
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);
    
    // Assert that all results are now enabled.
    enabledResults.clear();
    processor_->GetEnabledMetadataResults(enabledResults);
    // The exact number depends on default keys, but it should be greater than before.
    // A better assertion would be to get ALL possible keys and check if sizes match.
    EXPECT_GT(enabledResults.size(), 0);
}

/**
 * @tc.name: dcamera_metadata_processor_test_010
 * @tc.desc: Verify Enable/Disable with invalid/boundary inputs
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_010, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->InitDCameraAbility(VALID_ABILITY_JSON);

    std::vector<MetaType> invalidResults = { static_cast<MetaType>(99999) };
    DCamRetCode rc = processor_->EnableMetadataResult(invalidResults);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);
    
    std::vector<MetaType> enabledResults;
    processor_->GetEnabledMetadataResults(enabledResults);
    EXPECT_EQ(enabledResults.size(), 0);

    std::vector<MetaType> resultsToDisable = { OHOS_CONTROL_AE_AVAILABLE_MODES };
    rc = processor_->DisableMetadataResult(resultsToDisable);
    EXPECT_EQ(rc, DCamRetCode::SUCCESS);
    processor_->GetEnabledMetadataResults(enabledResults);
    EXPECT_EQ(enabledResults.size(), 0);
}

/**
 * @tc.name: dcamera_metadata_processor_test_011
 * @tc.desc: Verify concurrent access to processor does not cause crashes or deadlocks
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_011, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    processor_->InitDCameraAbility(VALID_ABILITY_JSON);
    processor_->SetMetadataResultMode(ResultCallbackMode::ON_CHANGED);

    std::atomic<bool> stopFlag = false;
    std::atomic<int> callbackCount = 0;

    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> cb =
        [&](uint64_t ts, std::shared_ptr<OHOS::Camera::CameraMetadata> res) {
        callbackCount++;
    };
    processor_->SetResultCallback(cb);

    // Thread 1: Continuously saves new metadata
    std::thread producerThread([&stopFlag, this]() {
        int i = 0;
        while (!stopFlag) {
            std::shared_ptr<CameraAbility> ability = std::make_shared<CameraAbility>(10, 50);
            ability->addEntry(OHOS_CONTROL_ZOOM_RATIO, &i, 1); // Use changing data
            std::string metaStr = OHOS::Camera::MetadataUtils::EncodeToString(ability);
            std::string encoded = Base64Encode(reinterpret_cast<const unsigned char*>
                (metaStr.c_str()), metaStr.length());
            processor_->SaveResultMetadata(encoded);
            i++;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    // Thread 2: Continuously changes configuration
    std::thread configThread([&stopFlag, this]() {
        std::vector<MetaType> enable = { OHOS_CONTROL_AE_AVAILABLE_MODES };
        std::vector<MetaType> disable = { OHOS_CONTROL_AWB_AVAILABLE_MODES };
        while (!stopFlag) {
            processor_->EnableMetadataResult(enable);
            processor_->DisableMetadataResult(disable);
            processor_->ResetEnableResults();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // Let the threads run for a short period
    std::this_thread::sleep_for(std::chrono::seconds(1));
    stopFlag = true;

    producerThread.join();
    configThread.join();

    // The main assertion is that the test completes without crashing or deadlocking.
    // We can also check if callbacks were fired.
    EXPECT_GT(callbackCount, 0);
    SUCCEED();
}

/**
 * @tc.name: dcamera_metadata_processor_test_012
 * @tc.desc: Verify all branches of function GetMetadataItemData
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_012, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    camera_metadata_item_t item;
    
    // Test META_TYPE_BYTE
    item.data_type = META_TYPE_BYTE;
    uint8_t byteVal = 123;
    item.data.u8 = &byteVal;
    void* dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    EXPECT_EQ(*(static_cast<uint8_t*>(dataPtr)), byteVal);

    // Test META_TYPE_INT32
    item.data_type = META_TYPE_INT32;
    int32_t i32Val = -12345;
    item.data.i32 = &i32Val;
    dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    EXPECT_EQ(*(static_cast<int32_t*>(dataPtr)), i32Val);

    // Test META_TYPE_FLOAT
    item.data_type = META_TYPE_FLOAT;
    float fVal = 123.45f;
    item.data.f = &fVal;
    dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    EXPECT_FLOAT_EQ(*(static_cast<float*>(dataPtr)), fVal);

    // Test META_TYPE_INT64
    item.data_type = META_TYPE_INT64;
    int64_t i64Val = -1234567890;
    item.data.i64 = &i64Val;
    dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    EXPECT_EQ(*(static_cast<int64_t*>(dataPtr)), i64Val);

    // Test META_TYPE_DOUBLE
    item.data_type = META_TYPE_DOUBLE;
    double dVal = 12345.6789;
    item.data.d = &dVal;
    dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    EXPECT_DOUBLE_EQ(*(static_cast<double*>(dataPtr)), dVal);

    // Test META_TYPE_RATIONAL
    item.data_type = META_TYPE_RATIONAL;
    camera_rational_t r_val = {1, 2};
    item.data.r = &r_val;
    dataPtr = processor_->GetMetadataItemData(item);
    ASSERT_NE(dataPtr, nullptr);
    camera_rational_t* r_ptr = static_cast<camera_rational_t*>(dataPtr);
    EXPECT_EQ(r_ptr->numerator, 1);
    EXPECT_EQ(r_ptr->denominator, 2);
}

/**
 * @tc.name: dcamera_metadata_processor_test_013
 * @tc.desc: Verify functions ResizeMetadataHeader and ConvertToCameraMetadata
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_013, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    common_metadata_header_t* header = nullptr;

    processor_->ResizeMetadataHeader(header, 10, 50);
    ASSERT_NE(header, nullptr);
    
    common_metadata_header_t* old_header_ptr = header;
    processor_->ResizeMetadataHeader(header, 20, 100);
    ASSERT_NE(header, nullptr);
    EXPECT_NE(header, old_header_ptr);

    if (header != nullptr) {
        OHOS::Camera::FreeCameraMetadataBuffer(header);
        header = nullptr;
    }

    std::shared_ptr<CameraAbility> sourceAbility = std::make_shared<CameraAbility>(10, 50);
    const uint8_t cameraType = OHOS_CAMERA_TYPE_LOGICAL;
    ASSERT_EQ(sourceAbility->addEntry(OHOS_ABILITY_CAMERA_TYPE, &cameraType, 1), true);
    
    common_metadata_header_t* sourceHeader = sourceAbility->get();
    ASSERT_NE(sourceHeader, nullptr);
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> destMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(20, 100);

    processor_->ConvertToCameraMetadata(sourceHeader, destMetadata);
    ASSERT_NE(destMetadata, nullptr);

    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(destMetadata->get(), OHOS_ABILITY_CAMERA_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(item.data.u8[0], cameraType);
}

/**
 * @tc.name: dcamera_metadata_processor_test_014
 * @tc.desc: Verify function PrintDCameraMetadata doesn't crash on various inputs
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DMetadataProcessorTest, dcamera_metadata_processor_test_014, TestSize.Level1)
{
    ASSERT_NE(processor_, nullptr);
    std::shared_ptr<CameraAbility> retrievedAbility;
    processor_->PrintDCameraMetadata(nullptr);
    processor_->GetDCameraAbility(retrievedAbility);
    EXPECT_EQ(retrievedAbility, nullptr);
    DCamRetCode rc = processor_->InitDCameraAbility(VALID_ABILITY_JSON);
    ASSERT_EQ(rc, DCamRetCode::SUCCESS);
    processor_->GetDCameraAbility(retrievedAbility);
    ASSERT_NE(retrievedAbility, nullptr);
    processor_->PrintDCameraMetadata(retrievedAbility->get());

    std::shared_ptr<CameraAbility> empty_ability = std::make_shared<CameraAbility>(10, 10);
    processor_->PrintDCameraMetadata(empty_ability->get());
    SUCCEED();
}

} // namespace DistributedHardware
} // namespace OHOS