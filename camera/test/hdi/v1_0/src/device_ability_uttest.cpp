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
    cameraTest = std::make_shared<OHOS::Camera::HdiCommon>();
    cameraTest->Init();
    cameraTest->Open();
}

void DeviceAbilityUtTest::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: print camera ability
 * @tc.desc: print camera ability
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(DeviceAbilityUtTest, Device_Ability_Hdi_001, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t *data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    std::string metaStr = FormatCameraMetadataToString(data);
    EXPECT_NE(metaStr.empty(), true);
    std::cout << "Device_Ability_001 start:" << std::endl << metaStr << std::endl <<
        "Device_Ability_001 end" << std::endl;
}
