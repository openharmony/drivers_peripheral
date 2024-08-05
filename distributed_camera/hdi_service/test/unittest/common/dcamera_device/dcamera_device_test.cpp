/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dcamera_device.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DCameraDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    sptr<DCameraDevice> dcameraDevice_ = nullptr;
};

constexpr const char* TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";
constexpr const char* TEST_CAMERA_DH_ID_0 = "camera_0";
constexpr const char* TEST_ABILITY = R"({"CodecType": ["avenc_mpeg4"],
    "Position": "BACK",
    "ProtocolVer": "1.0",
    "MetaData": "",
    "Photo": {
        "OutputFormat": [2, 4],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
            "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "4": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
            "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    },
    "Preview": {
        "OutputFormat": [2, 3],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "3": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    },
    "Video": {
        "OutputFormat": [2, 3],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "3": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    }})";

void DCameraDeviceTest::SetUpTestCase(void)
{
}

void DCameraDeviceTest::TearDownTestCase(void)
{
}

void DCameraDeviceTest::SetUp(void)
{
    DHBase dhBase = {TEST_DEVICE_ID, TEST_CAMERA_DH_ID_0};
    dcameraDevice_ = sptr<DCameraDevice>(new (std::nothrow) DCameraDevice(dhBase, TEST_ABILITY, TEST_ABILITY));
}

void DCameraDeviceTest::TearDown(void)
{
}

/**
 * @tc.name: dcamera_device_test_001
 * @tc.desc: Verify SetResultMode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_001, TestSize.Level0)
{
    EXPECT_EQ(false, dcameraDevice_ == nullptr);

    ResultCallbackMode mode = PER_FRAME;
    int32_t rc = dcameraDevice_->SetResultMode(mode);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_002
 * @tc.desc: Verify GetEnabledResults
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_002, TestSize.Level1)
{
    EXPECT_EQ(false, dcameraDevice_ == nullptr);

    std::vector<int32_t> results;
    int32_t rc = dcameraDevice_->GetEnabledResults(results);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_003
 * @tc.desc: Verify SetResultMode ON_CHANGED
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_003, TestSize.Level1)
{
    EXPECT_EQ(false, dcameraDevice_ == nullptr);

    ResultCallbackMode mode = ON_CHANGED;
    int32_t rc = dcameraDevice_->SetResultMode(mode);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);

    std::vector<int32_t> results;
    rc = dcameraDevice_->GetEnabledResults(results);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_004
 * @tc.desc: Verify GetDCameraAbility
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_004, TestSize.Level1)
{
    EXPECT_EQ(false, dcameraDevice_ == nullptr);

    std::shared_ptr<CameraAbility> ability = nullptr;
    CamRetCode rc = dcameraDevice_->GetDCameraAbility(ability);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dcamera_device_test_005
 * @tc.desc: Verify GetDCameraAbility
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraDeviceTest, dcamera_device_test_005, TestSize.Level1)
{
    EXPECT_EQ(false, dcameraDevice_ == nullptr);

    std::shared_ptr<CameraAbility> ability = nullptr;
    std::string sinkAbility = "sink";
    dcameraDevice_->SetDcameraAbility(sinkAbility);
    CamRetCode rc = dcameraDevice_->GetDCameraAbility(ability);
    EXPECT_EQ(true, rc == CamRetCode::INVALID_ARGUMENT);

    dcameraDevice_->SetDcameraAbility(TEST_ABILITY);
    rc = dcameraDevice_->GetDCameraAbility(ability);
    EXPECT_EQ(true, rc == CamRetCode::NO_ERROR);
}
}
}