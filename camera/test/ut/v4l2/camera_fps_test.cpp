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
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->Init();
}
void CameraFpsTest::TearDown(void)
{
    cameraBase_->Close();
}

void CameraFpsTest::GetFpsRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    fpsRange_.clear();
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_ABILITY_FPS_RANGES error.");
    }

    uint32_t count = entry.count;
    for (int i = 0 ; i < count; i++) {
        fpsRange_.push_back(*(entry.data.i32 + i));
    }

    for (auto it = fpsRange_.begin(); it != fpsRange_.end(); it++) {
        CAMERA_LOGI("fpsRange : %{public}d", *it);
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
    if (cameraBase_->ability == nullptr) {
        CAMERA_LOGE("ability is null.");
        return;
    }
    GetFpsRange(cameraBase_->ability);

    // get the stream manager
    cameraBase_->AchieveStreamOperator();

    // enable result
    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_FPS_RANGES);
    cameraBase_->cameraDevice->EnableResult(resultsList);

    // start stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);

    // updateSettings
    constexpr uint32_t itemCapacity = 100;
    constexpr uint32_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        itemCapacity, dataCapacity);
    std::vector<int32_t> fpsRange;
    fpsRange.push_back(fpsRange_[0]);
    fpsRange.push_back(fpsRange_[1]);
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }

    // get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}