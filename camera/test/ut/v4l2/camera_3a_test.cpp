/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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

#include "camera_3a_test.h"

constexpr int ITEM_CAPACITY_SIZE = 100;
constexpr int DATA_CAPACITY_SIZE = 2000;

void UtestCamera3ATest::SetUpTestCase(void)
{}
void UtestCamera3ATest::TearDownTestCase(void)
{}
void UtestCamera3ATest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestCamera3ATest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: updateSettings AE
  * @tc.desc: Preview，updateSettings OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0001)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "then UpdateSettings OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // Configure preview stream information
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    std::cout << "==========[test log] UpdateSettings, exposure for 10s." << std::endl;
    sleep(3); // update settings, exposure for 3s

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_AUTO, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0002)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_AUTO, success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // Configure stream information
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_AUTO." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    sleep(2); // update settings, AWB mode auto for 2s.

    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_INCANDESCENT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0003)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_INCANDESCENT, success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_INCANDESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings,";
    std::cout << "awb mode: OHOS_CAMERA_AWB_MODE_INCANDESCENT" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_FLUORESCENT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0004) // 3A mode white balance blue scene
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_FLUORESCENT, success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // Configure stream information
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode =  AWB_MODE_WARM_FLUORESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_AUTO." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    sleep(2); // update settings, AWB mode auto for 2s.

    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0005)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT, ";
    std::cout << "success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "awb mode: OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_DAYLIGHT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0006)
{
    std::cout << "==========[test log] Preview, ";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_DAYLIGHT, success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_DAYLIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_DAYLIGHT" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    sleep(3); // update settings, AWB mode daylight for 3s.

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0007) // 3A mode reset
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT,";
    std::cout << "success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "awb mode: OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0008)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_TWILIGHT, ";
    std::cout << "success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // Configure stream information
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_TWILIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_TWILIGHT" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0009) // 3A mode white balance yellow scene
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_SHADE, success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_SHADE;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_SHADE" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AWB
  * @tc.desc: Preview，updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_OFF, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0010)
{
    std::cout << "==========[test log] Preview，";
    std::cout << "updateSettings OHOS_CAMERA_AWB_MODE-OHOS_CAMERA_AWB_MODE_OFF, success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_OFF;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::cout << "==========[test log] UpdateSettings, awb mode: OHOS_CAMERA_AWB_MODE_OFF" << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);

    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings reset
  * @tc.desc: Preview set 3A, then close device, and preview, 3A is reset.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0030)
{
    std::cout << "==========[test log] Preview set 3A, then close device, and preview, 3A is reset." << std::endl;
    std::cout << "==========[test log] The 1st time set 3A." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Start capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    std::cout << "==========[test log] UpdateSettings, exposure for 3s." << std::endl;
    sleep(3);  // update settings, exposure for 3s
    // Post action of stream operation
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);

    // Turn off the device
    cameraBase->Close();
    std::cout << "cameraDevice->Close" << std::endl;
    std::cout << "==========[test log] Close device, and preview, 3A is reset." << std::endl;
    cameraBase->Init();
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings different 3A params
  * @tc.desc: Preview, updatesetting different 3A params together.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0031) // 3A mode white balance green scene
{
    std::cout << "==========[test log] Preview, updatesetting different 3A params together." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_TWILIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    std::cout << "==========[test log] UpdateSettings, exposure for 10s." << std::endl;
    sleep(3); // update settings, exposure for 3s
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: updateSettings AE
  * @tc.desc: UpdateSettings-OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0040)
{
    std::cout << "UpdateSettings-OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(cameraBase->rc, Camera::NO_ERROR);
    sleep(3); // waiting resource release for 3s.
}

/**
  * @tc.name: updateSettings AWB without preview
  * @tc.desc: UpdateSettings-OHOS_CAMERA_AWB_MODE, without preview, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestCamera3ATest, camera_3a_0041)
{
    std::cout << "UpdateSettings-OHOS_CAMERA_AWB_MODE, success." << std::endl;

    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    EXPECT_EQ(cameraBase->cameraDevice->UpdateSettings(meta), Camera::NO_ERROR);
}
