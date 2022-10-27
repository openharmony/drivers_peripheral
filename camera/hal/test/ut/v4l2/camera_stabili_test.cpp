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
#include "camera_stabili_test.h"

using namespace testing::ext;

void CameraStabiliTest::SetUpTestCase(void)
{}
void CameraStabiliTest::TearDownTestCase(void)
{}
void CameraStabiliTest::SetUp(void)
{
    if (display_ == nullptr) {
        display_ = std::make_shared<TestDisplay>();
    }
    display_->Init();
}
void CameraStabiliTest::TearDown(void)
{
    display_->Close();
}

void CameraStabiliTest::GetAvalialbleVideoStabilizationModes(
    std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    videoStabilizationAvailableModes_.clear();
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &entry);
    if (ret != 0) {
        std::cout << "==========[test log] get OHOS_ABILITY_VIDEO_STABILIZATION_MODES error." << std::endl;
    }
    uint32_t count = entry.count;
    for (int i = 0 ; i < count; i++) {
        videoStabilizationAvailableModes_.push_back(*(entry.data.u8 + i));
    }
    for (auto it = videoStabilizationAvailableModes_.begin(); it != videoStabilizationAvailableModes_.end(); it++) {
        std::cout << "==========[test log] videoStabilizationAvailableModes : " << (int)*it << std::endl;
    }
}

/**
  * @tc.name: stabili setting
  * @tc.desc: UpdateSettings, OHOS_CONTROL_VIDEO_STABILIZATION_MODE.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(CameraStabiliTest, camera_stabili_001, TestSize.Level1)
{
    // get camera ability
    if (display_->ability == nullptr) {
        std::cout << "==========[test log] ability is null." << std::endl;
        return;
    }
    GetAvalialbleVideoStabilizationModes(display_->ability);

    // get the stream manager
    display_->AchieveStreamOperator();

    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);

    // updateSettings
    constexpr uint32_t ITEM_CAPACITY = 100;
    constexpr uint32_t DATA_CAPACITY = 2000;
    constexpr uint32_t DATA_COUNT = 1;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t videoStabiliMode = videoStabilizationAvailableModes_[0];
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings success" << std::endl;
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