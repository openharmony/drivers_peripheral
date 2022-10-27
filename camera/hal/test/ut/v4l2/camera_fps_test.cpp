/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "camera_fps_test.h"

using namespace testing::ext;

void CameraFpsTest::SetUpTestCase(void)
{}
void CameraFpsTest::TearDownTestCase(void)
{}
void CameraFpsTest::SetUp(void)
{
    if (display_ == nullptr) {
        display_ = std::make_shared<TestDisplay>();
    }
    display_->Init();
}
void CameraFpsTest::TearDown(void)
{
    display_->Close();
}

void CameraFpsTest::GetFpsRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    fpsRange_.clear();
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
    if (ret != 0) {
        std::cout << "==========[test log] get OHOS_ABILITY_FPS_RANGES error." << std::endl;
    }

    uint32_t count = entry.count;
    for (int i = 0 ; i < count; i++) {
        fpsRange_.push_back(*(entry.data.i32 + i));
    }

    for (auto it = fpsRange_.begin(); it != fpsRange_.end(); it++) {
        std::cout << "==========[test log] fpsRange : " << *it << std::endl;
    }
}

/**
  * @tc.name: fps Setting
  * @tc.desc: UpdateSettings, fps.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(CameraFpsTest, camera_fps_001, TestSize.Level1)
{
    // get camera ability
    if (display_->ability == nullptr) {
        std::cout << "==========[test log] ability is null." << std::endl;
        return;
    }
    GetFpsRange(display_->ability);

    // get the stream manager
    display_->AchieveStreamOperator();

    // enable result
    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CONTROL_FPS_RANGES);
    display_->cameraDevice->EnableResult(resultsList);

    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);

    // updateSettings
    constexpr uint32_t ITEM_CAPACITY = 100;
    constexpr uint32_t DATA_CAPACITY = 2000;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        ITEM_CAPACITY, DATA_CAPACITY);
    std::vector<int32_t> fpsRange;
    fpsRange.push_back(fpsRange_[0]);
    fpsRange.push_back(fpsRange_[1]);
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings success." << std::endl;
    } else {
        std::cout << "==========[test log] UpdateSettings fail, rc = " << display_->rc << std::endl;
    }

    // get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);

    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}