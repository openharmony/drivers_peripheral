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
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->Init();
}
void CameraStabiliTest::TearDown(void)
{
    cameraBase_->Close();
}

void CameraStabiliTest::GetAvalialbleVideoStabilizationModes(
    std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    videoStabilizationAvailableModes_.clear();
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_ABILITY_VIDEO_STABILIZATION_MODES error.");
    }
    uint32_t count = entry.count;
    for (int i = 0 ; i < count; i++) {
        videoStabilizationAvailableModes_.push_back(*(entry.data.u8 + i));
    }
    for (auto it = videoStabilizationAvailableModes_.begin(); it != videoStabilizationAvailableModes_.end(); it++) {
        CAMERA_LOGI("videoStabilizationAvailableModes: %{public}d", static_cast<int>(*it));
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
    if (cameraBase_->ability == nullptr) {
        CAMERA_LOGE("ability is null.");
        return;
    }
    GetAvalialbleVideoStabilizationModes(cameraBase_->ability);

    // get the stream manager
    cameraBase_->AchieveStreamOperator();

    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);

    // updateSettings
    constexpr uint32_t itemCapacity = 100;
    constexpr uint32_t dataCapacity = 2000;
    constexpr uint32_t dataCount = 1;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        itemCapacity, dataCapacity);
    uint8_t videoStabiliMode = videoStabilizationAvailableModes_[0];
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, dataCount);
    const int32_t deviceStreamId = cameraBase_->STREAM_ID_VIDEO;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }

    // get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: stabili setting
  * @tc.desc: preview,video then UpdateSettings, OHOS_CONTROL_VIDEO_STABILIZATION_MODE.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(CameraStabiliTest, camera_stabili_002, TestSize.Level1)
{
    // get camera ability
    if (cameraBase_->ability == nullptr) {
        CAMERA_LOGE("ability is null.");
        return;
    }
    GetAvalialbleVideoStabilizationModes(cameraBase_->ability);

    // get the stream manager
    cameraBase_->AchieveStreamOperator();

    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);

    // get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

    // updateSettings
    constexpr uint32_t itemCapacity = 100;
    constexpr uint32_t dataCapacity = 2000;
    constexpr uint32_t dataCount = 1;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        itemCapacity, dataCapacity);
    uint8_t videoStabiliMode = videoStabilizationAvailableModes_[0];
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, dataCount);
    const int32_t deviceStreamId = cameraBase_->STREAM_ID_VIDEO;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }
    sleep(3);

    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}
