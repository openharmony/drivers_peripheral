/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "usb_camera_3a_test.h"

const TestMetadata CAMERA_3A_TEST_SETS[] = {
    // test OHOS_CONTROL_EXPOSURE_MODE
    {
        .tag =OHOS_CONTROL_EXPOSURE_MODE,
        .value = OHOS_CAMERA_EXPOSURE_MODE_MANUAL
    },
    {
        .tag =OHOS_CONTROL_EXPOSURE_MODE,
        .value = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO
    },
    {
        .tag =OHOS_CONTROL_EXPOSURE_MODE,
        .value = OHOS_CAMERA_EXPOSURE_MODE_AUTO
    },
    {
        .tag =OHOS_CONTROL_EXPOSURE_MODE,
        .value = OHOS_CAMERA_EXPOSURE_MODE_LOCKED
    },

    // test OHOS_CONTROL_AE_LOCK
    {
        .tag =OHOS_CONTROL_AE_LOCK,
        .value = OHOS_CAMERA_AE_LOCK_ON
    },
    {
        .tag =OHOS_CONTROL_AE_LOCK,
        .value = OHOS_CAMERA_AE_LOCK_OFF
    },

    // test OHOS_CONTROL_FOCUS_MODE
    {
        .tag =OHOS_CONTROL_FOCUS_MODE,
        .value = OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO
    },
    {
        .tag =OHOS_CONTROL_FOCUS_MODE,
        .value = OHOS_CAMERA_FOCUS_MODE_MANUAL
    },
    {
        .tag =OHOS_CONTROL_FOCUS_MODE,
        .value = OHOS_CAMERA_FOCUS_MODE_AUTO
    },
    {
        .tag =OHOS_CONTROL_FOCUS_MODE,
        .value = OHOS_CAMERA_FOCUS_MODE_LOCKED
    },

    // test OHOS_SENSOR_EXPOSURE_TIME
    {
        .tag =OHOS_SENSOR_EXPOSURE_TIME,
        .value = 1
    },

    // test OHOS_CONTROL_METER_MODE
    {
        .tag =OHOS_CONTROL_METER_MODE,
        .value = OHOS_CAMERA_SPOT_METERING
    },
    {
        .tag =OHOS_CONTROL_METER_MODE,
        .value = OHOS_CAMERA_REGION_METERING
    },
    {
        .tag =OHOS_CONTROL_METER_MODE,
        .value = OHOS_CAMERA_OVERALL_METERING
    },

    // test OHOS_CONTROL_AWB_MODE
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_AUTO
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_OFF
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_TWILIGHT
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_DAYLIGHT
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT
    },
    {
        .tag =OHOS_CONTROL_AWB_MODE,
        .value = OHOS_CAMERA_AWB_MODE_SHADE
    },

    // test OHOS_CONTROL_AWB_LOCK
    {
        .tag =OHOS_CONTROL_AWB_LOCK,
        .value = OHOS_CAMERA_AWB_LOCK_ON
    },
    {
        .tag =OHOS_CONTROL_AWB_LOCK,
        .value = OHOS_CAMERA_AWB_LOCK_OFF
    }
};

void UtestUSBCamera3ATest::SetUpTestCase(void)
{}

void UtestUSBCamera3ATest::TearDownTestCase(void)
{}

void UtestUSBCamera3ATest::SetUp(void)
{
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->UsbInit();
}

void UtestUSBCamera3ATest::TearDown(void)
{
    cameraBase_->Close();
}

bool UtestUSBCamera3ATest::RunCamera3A(TestMetadata& metadata)
{
    // Get the device manager
    cameraBase_->OpenUsbCamera();
    ability_ = cameraBase_->GetCameraAbility();
    EXPECT_NE(ability_, nullptr);

    // Get the stream manager
    cameraBase_->AchieveStreamOperator();

    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);

     // updateSettings
    const uint32_t itemCapacity = 100;
    const uint32_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        itemCapacity, dataCapacity);

    int ohosTag = metadata.tag;
    const uint8_t tagVal = metadata.value;
    if (!meta->addEntry(ohosTag, &tagVal, 1)) {
        std::cout << GetCameraMetadataItemName(ohosTag) << "(" << ohosTag << ")" << "add failed" << std::endl;
        return false;
    }
    std::cout << GetCameraMetadataItemName(ohosTag) << "(" << ohosTag << ")" << " add success" << std::endl;
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "UpdateSettings (" << ohosTag << ")" << " success" << std::endl;
    } else {
        std::cout << "UpdateSettings (" << ohosTag << ")" << " fail" << std::endl;
        return false;
    }

    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
    return cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR;
}

TEST_P(UtestUSBCamera3ATest, UtestUSBCamera3ATest)
{
    TestMetadata params = GetParam();
    bool ret = RunCamera3A(params);
    EXPECT_EQ(ret, true);
}

INSTANTIATE_TEST_SUITE_P(Test3A, UtestUSBCamera3ATest, ::testing::ValuesIn(CAMERA_3A_TEST_SETS));