/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "device_ability_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void DeviceAbilityUtTest::SetUpTestCase(void) {}
void DeviceAbilityUtTest::TearDownTestCase(void) {}
void DeviceAbilityUtTest::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init();
    cameraTest->Open();
}

void DeviceAbilityUtTest::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Device_Ability_Hdi_0001
 * @tc.desc: OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(DeviceAbilityUtTest, Device_Ability_Hdi_0001, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry);
    if (ret == 0 && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value start.");
        constexpr size_t step = 10; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGE("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value end.");
    }
}
