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
#include "camera_ability_test.h"

using namespace testing::ext;

void CameraAbilityTest::SetUpTestCase(void)
{}

void CameraAbilityTest::TearDownTestCase(void)
{}

void CameraAbilityTest::SetUp(void)
{
    if (display_ == nullptr) {
        display_ = std::make_shared<TestDisplay>();
    }
    display_->Init();
}

OHOS::Camera::RetCode CameraAbilityTest::GetSensorOrientation(
    std::shared_ptr<OHOS::Camera::CameraAbility> &ability)
{
    common_metadata_header_t* data = display_->ability->get();
    int32_t sensorOrientation;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_SENSOR_ORIENTATION, &entry);
    if (ret != 0) {
        std::cout << "==========[test log] get OHOS_SENSOR_ORIENTATION error." << std::endl;
        return OHOS::Camera::RC_ERROR;
    }
    sensorOrientation = *(entry.data.i32);
    std::cout << "==========[test log] get sensorOrientation =" << sensorOrientation << std::endl;
    return OHOS::Camera::RC_OK;
}

void CameraAbilityTest::TearDown(void)
{
    display_->Close();
}

/**
  * @tc.name: get camera ability
  * @tc.desc: get camera ability
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(CameraAbilityTest, camera_ability_001, TestSize.Level1)
{
    if (display_->ability == nullptr) {
        std::cout << "==========[test log] ability is null." << std::endl;
        return;
    }
    GetSensorOrientation(display_->ability);
}
