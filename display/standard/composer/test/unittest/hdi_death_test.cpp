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

#include "hdi_death_test.h"
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "display_test.h"
#include "display_test_utils.h"
#include "hdi_test_device.h"
#include "hdi_test_device_common.h"
#include "hdi_test_display.h"

using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::TEST;
using namespace testing::ext;

std::shared_ptr<IDisplayComposerInterface> composerDevice {};

void DeathTest::SetUp()
{
    composerDevice.reset(IDisplayComposerInterface::Get());
}

void ComposerDideRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if(remote == nullptr) { 
        return;
    }
    DISPLAY_TEST_LOGD("display composer service dead");
}

HWTEST_F(DeathTest, test_AddDeathRecipient, TestSize.Level1)
{
    composerDevice.reset(IDisplayComposerInterface::Get());
    sptr<IRemoteObject::DeathRecipient> recipient = new ComposerDideRecipient();
    auto ret = composerDevice->AddDeathRecipient(recipient);
    EXPECT_EQ(ret, true);
    system("killall display_composer_host");
}

HWTEST_F(DeathTest, test_RemoveDeathRecipient, TestSize.Level1)
{   
    composerDevice.reset(IDisplayComposerInterface::Get());
    sptr<IRemoteObject::DeathRecipient> recipient = new ComposerDideRecipient();
    auto ret = composerDevice->AddDeathRecipient(recipient);
    EXPECT_EQ(ret, true);

    ret = composerDevice->RemoveDeathRecipient();
    EXPECT_EQ(ret, true);

    system("killall display_composer_host");
}