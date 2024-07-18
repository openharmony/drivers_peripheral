/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdi_test.h"

constexpr int ITEM_CAPACITY_SIZE = 100;
constexpr int DATA_CAPACITY_SIZE = 2000;

void UtestHdiTest::SetUpTestCase(void){}
void UtestHdiTest::TearDownTestCase(void){}
void UtestHdiTest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestHdiTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: GetCameraIds
  * @tc.desc: CamRetCode GetCameraIds([out] String[] ids);
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0010)
{
    std::cout << "==========[test log] GetCameraIds([out] String[] ids)." << std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        sleep(3); // waiting 3s, prepare for execute GetCameraIds.
        cameraBase->rc = cameraBase->cameraHost->GetCameraIds(cameraBase->cameraIds);
        EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
        EXPECT_LT(0, cameraBase->cameraIds.size());
        std::cout << "==========[test log] cameraIds.size()= ."<< cameraBase->cameraIds.size() << std::endl;
    }
}

/**
  * @tc.name: GetCameraAbility
  * @tc.desc: GetCameraAbility, normal cameraId.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0020)
{
    std::cout << "==========[test log] GetCameraAbility, normal cameraId." << std::endl;
    std::shared_ptr<CameraAbility> ability;
    if (cameraBase->cameraDevice == nullptr) {
        sleep(3); // waiting 3s, prepare for execute GetCameraIds.
        cameraBase->rc = cameraBase->cameraHost->GetCameraIds(cameraBase->cameraIds);
        EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
        for (int i = 0; i < cameraBase->cameraIds.size(); i++) {
            cameraBase->rc = cameraBase->cameraHost->GetCameraAbility(cameraBase->cameraIds[i], ability);
            std::cout << "==========[test log] GetCameraAbility, cameraid = ";
            std::cout << cameraBase->cameraIds[i] << std::endl;
            EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
        }
    }
}

/**
  * @tc.name: GetCameraAbility
  * @tc.desc: GetCameraAbility, abnormal cameraId = 'abc'.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0021)
{
    std::cout << "==========[test log] GetCameraAbility, abnormal cameraId = 'abc'." << std::endl;
    std::shared_ptr<CameraAbility> ability;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "abc";
        sleep(3); // waiting 3s, prepare for execute GetCameraAbility.
        cameraBase->rc = cameraBase->cameraHost->GetCameraAbility(cameraId, ability);
        std::cout << "==========[test log] cameraBase->rc ="<< cameraBase->rc << std::endl;
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: GetCameraAbility
  * @tc.desc: GetCameraAbility, abnormal cameraId = ""
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0022)
{
    std::cout << "==========[test log] GetCameraAbility, abnormal cameraId = ''." << std::endl;
    std::shared_ptr<CameraAbility> ability;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "";
        sleep(2); // waiting 2s, prepare for execute GetCameraAbility.
        cameraBase->rc = cameraBase->cameraHost->GetCameraAbility(cameraId, ability);
        std::cout << "==========[test log] cameraBase->rc ="<< cameraBase->rc << std::endl;
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, normal cameraId.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0030)
{
    std::cout << "==========[test log] OpenCamera, normal cameraId."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        sleep(3); // waiting 3s, prepare for execute GetCameraIds.
        cameraBase->cameraHost->GetCameraIds(cameraBase->cameraIds);
        const std::shared_ptr<ICameraDeviceCallback> callback =
            std::make_shared<ICameraDeviceCallback>();
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraBase->cameraIds.front(),
            callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
        if (cameraBase->rc != NO_ERROR || cameraBase->cameraDevice == nullptr) {
            std::cout << "==========[test log] OpenCamera failed." << std::endl;
            return;
        }
        std::cout << "==========[test log] OpenCamera success." << std::endl;
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, cameraID is not found.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0031)
{
    std::cout << "==========[test log] OpenCamera, cameraID is not found."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "qwerty";
        const std::shared_ptr<ICameraDeviceCallback> callback =
            std::make_shared<ICameraDeviceCallback>();
        sleep(3); // waiting 3s, prepare for execute OpenCamera.
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, cameraID is illegal.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0032)
{
    std::cout << "==========[test log] OpenCamera, cameraID is illegal."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "1";
        const std::shared_ptr<ICameraDeviceCallback> callback =
            std::make_shared<ICameraDeviceCallback>();
        sleep(3); // waiting 3s, prepare for execute OpenCamera.
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, cameraID is Empty.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0033)
{
    std::cout << "==========[test log] OpenCamera, cameraID is Empty."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "";
        const std::shared_ptr<ICameraDeviceCallback> callback =
            std::make_shared<ICameraDeviceCallback>();
        sleep(3); // waiting 3s, prepare for execute OpenCamera.
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, Callback is Null.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0034)
{
    std::cout << "==========[test log] OpenCamera, Callback is Null."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        sleep(3); // waiting 3s, prepare for execute GetCameraIds.
        cameraBase->cameraHost->GetCameraIds(cameraBase->cameraIds);
        const std::shared_ptr<ICameraDeviceCallback> callback = nullptr;
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraBase->cameraIds.front(),
            callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: cameraID is not found, callback is null.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0035)
{
    std::cout << "==========[test log] OpenCamera, cameraID is not found, callback is null."<< std::endl;
    if (cameraBase->cameraDevice == nullptr) {
        std::string cameraId = "abc";
        const std::shared_ptr<ICameraDeviceCallback> callback = nullptr;
        sleep(3); // waiting 3s, prepare for execute OpenCamera.
        cameraBase->rc = cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
    }
}

/**
  * @tc.name: GetStreamOprator
  * @tc.desc: GetStreamOprator, normal callback input.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0050)
{
    std::cout << "==========[test log] GetStreamOprator, normal callback input." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    cameraBase->streamOperatorCallback = std::make_shared<IStreamOperatorCallback>();
    cameraBase->rc = cameraBase->cameraDevice->GetStreamOperator(cameraBase->streamOperatorCallback,
        cameraBase->streamOperator);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: GetStreamOprator
  * @tc.desc: GetStreamOprator, callback is nullptr.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0051)
{
    std::cout << "==========[test log] GetStreamOprator, normal callback input." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    cameraBase->streamOperatorCallback = nullptr;
    cameraBase->rc = cameraBase->cameraDevice->GetStreamOperator(cameraBase->streamOperatorCallback,
        cameraBase->streamOperator);
    EXPECT_EQ(true, cameraBase->rc == INVALID_ARGUMENT);
}

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0060)
{
    std::cout << "==========[test log] UpdateSettings, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_AUTO.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0061)
{
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_AUTO." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_TWILIGHT.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0063)
{
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_TWILIGHT." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_TWILIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_FLUORESCENT.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0065)
{
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_FLUORESCENT." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_FLUORESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0066)
{
    std::cout << "==========[test log] UpdateSettings, ";
    std::cout << "OHOS_CAMERA_AWB_MODE:OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT." << std::endl;
    sleep(3); // waiting 3s, prepare for execute OpenCamera.
    cameraBase->OpenCamera();
    // Issue 3A parameters
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    cameraBase->rc = cameraBase->cameraDevice->UpdateSettings(meta);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: SetResultMode
  * @tc.desc: SetResultMode is PER_FRAME.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0070)
{
    std::cout << "==========[test log] SetResultMode is PER_FRAME." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    std::vector<OHOS::Camera::MetaType> enableTypes;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(enableTypes);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    for (const auto &type : enableTypes) {
        std::cout << "==========[test log] type = " << type << std::endl;
    }
    cameraBase->rc = cameraBase->cameraDevice->SetResultMode(Camera::PER_FRAME);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: SetResultMode
  * @tc.desc: SetResultMode is ON_CHANGED.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0071)
{
    std::cout << "==========[test log] SetResultMode is PER_FRAME." << std::endl;
    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    std::vector<OHOS::Camera::MetaType> enableTypes;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(enableTypes);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    for (const auto &type : enableTypes) {
        std::cout << "==========[test log] type = " << type << std::endl;
    }
    cameraBase->rc = cameraBase->cameraDevice->SetResultMode(Camera::ON_CHANGED);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: GetEnabledReuslts
  * @tc.desc: GetEnabledReuslts expected success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0080)
{
    std::cout << "==========[test log] GetEnabledReuslts expected success." << std::endl;
    std::vector<OHOS::Camera::MetaType> results;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(results);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "GetEnabledReuslts is :" << std::endl;
    for (int i = 0; i<results.size(); ++i) {
        std::cout << results.at(i) << std::endl;
    }
}

/**
  * @tc.name: EnableResult
  * @tc.desc: EnableResult one tag, without preview, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0090)
{
    std::cout << "==========[test log] EnableResult one tag, without preview, success." << std::endl;
    // Get the parameter tag currently supported by the device
    std::cout << "==========[test log] 1. Get the tags..." << std::endl;
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    std::cout << "resultsOriginal.size = " << resultsOriginal.size() << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    // add this tag
    std::vector<OHOS::Camera::MetaType> enableTag;
    std::cout << "==========[test log] 2. Enable the tag: " << resultsOriginal[0] << std::endl;
    enableTag.push_back(resultsOriginal[1]);
    cameraBase->rc = cameraBase->cameraDevice->EnableResult(enableTag);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: EnableResult
  * @tc.desc: EnableResult multiple tags, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0091)
{
    std::cout << "==========[test log] EnableResult multiple tags, success." << std::endl;
    // Get the parameter tag currently supported by the device
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // Disable all tags
    std::cout << "then, disable the tag..." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->DisabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // Get the parameter tag currently supported by the device again
    std::vector<OHOS::Camera::MetaType> results;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    EXPECT_GT(results.size(), 0);

    // Add multiple tags
    std::cout << "then, enable the tag..." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->EnableResult(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // Get the parameter tag currently supported by the device again
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(results);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: EnableResult
  * @tc.desc: EnableResult error tag, expected success .
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0092)
{
    std::cout << "==========[test log] EnableResult error tag, expected fail." << std::endl;
    // Get the parameter tag currently supported by the device
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // add a tag
    std::vector<OHOS::Camera::MetaType> enableTag;
    enableTag.push_back(0);
    std::cout << "then, enable the tag..." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->EnableResult(enableTag);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: EnableResult
  * @tc.desc: DisableResult one tag, without preview, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0100)
{
    std::cout << "==========[test log] DisEnabledReuslts, expected success." << std::endl;
    // Get the parameter tag currently supported by the device
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "==========[test log] GetEnabledReuslts, size = " << resultsOriginal.size() << std::endl;

    // disable a tag
    std::vector<OHOS::Camera::MetaType> disableTag;
    disableTag.push_back(resultsOriginal[0]);
    cameraBase->rc = cameraBase->cameraDevice->DisableResult(disableTag);
    std::cout << "rc = " << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "==========[test log] DisableResult the tag:" << resultsOriginal[0] << std::endl;

    // Get the parameter tag currently supported by the device again
    std::vector<OHOS::Camera::MetaType> results;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(results);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: EnableResult
  * @tc.desc: DisableResult all tag, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0101)
{
    std::cout << "==========[test log] DisableResult all tag, success." << std::endl;
    // Get the parameter tag currently supported by the device
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // Disable all tags
    std::cout << "then, disable the tag..." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->DisableResult(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // Get the parameter tag currently supported by the device again
    std::vector<OHOS::Camera::MetaType> results;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(results);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: EnableResult
  * @tc.desc: DisableResult error tag, expected fail.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0102)
{
    std::cout << "==========[test log] DisableResult error tag, expected fail." << std::endl;
    // Get the parameter tag currently supported by the device
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(resultsOriginal);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);

    // disable a tag
    std::vector<OHOS::Camera::MetaType> disableTag;
    disableTag.push_back(0);
    std::cout << "then, disenable the tag..." << std::endl;
    cameraBase->rc = cameraBase->cameraDevice->DisableResult(disableTag);
    std::cout << "==========[test log] rc = " << cameraBase->rc << std::endl;
    EXPECT_EQ(false, cameraBase->rc == NO_ERROR);

    // Get the parameter tag currently supported by the device again
    std::vector<OHOS::Camera::MetaType> results;
    cameraBase->rc = cameraBase->cameraDevice->GetEnabledReuslts(results);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
}

/**
  * @tc.name: Close
  * @tc.desc: Close the device.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiTest, camera_hdi_0110)
{
    std::cout << "==========[test log] Close the device." << std::endl;
    EXPECT_EQ(false, cameraBase->cameraDevice == nullptr);
    if (cameraBase->cameraDevice != nullptr) {
        cameraBase->cameraDevice->Close();
        std::cout << "==========[test log] cameraBase->cameraDevice->Close()." << std::endl;
        cameraBase->cameraDevice = nullptr;
    }
}