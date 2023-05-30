/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "death_test.h"
#include <securec.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "gtest/gtest.h"
#include "v1_0/display_composer_type.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace testing::ext;

static bool g_isServiceDead = false;

void BufferDiedRecipient::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject>& remote)
{
    if (remote == nullptr) {
        return;
    }
    EXPECT_EQ(g_isServiceDead, true);
}

HWTEST_F(DeathTest, test_AddDeathRecipient, TestSize.Level1)
{
    displayBuffer_.reset(IDisplayBuffer::Get());
    ASSERT_TRUE(displayBuffer_ != nullptr);
    sptr<IRemoteObject::DeathRecipient> recipient = new BufferDiedRecipient();
    ASSERT_TRUE(recipient != nullptr);
    auto ret = displayBuffer_->AddDeathRecipient(recipient);
    EXPECT_EQ(ret, true);
    g_isServiceDead = true;
    system("killall allocator_host");
}

HWTEST_F(DeathTest, test_RemoveDeathRecipient, TestSize.Level1)
{
    displayBuffer_.reset(IDisplayBuffer::Get());
    ASSERT_TRUE(displayBuffer_ != nullptr);
    sptr<IRemoteObject::DeathRecipient> recipient = new BufferDiedRecipient();
    ASSERT_TRUE(recipient != nullptr);
    auto ret = displayBuffer_->AddDeathRecipient(recipient);
    EXPECT_EQ(ret, true);

    ret = displayBuffer_->RemoveDeathRecipient();
    EXPECT_EQ(ret, true);
    g_isServiceDead = true;
    system("killall allocator_host");
}
} // OHOS
} // HDI
} // DISPLAY
} // TEST