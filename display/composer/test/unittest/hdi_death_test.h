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

#ifndef HDI_COMPOSER_UT_H
#define HDI_COMPOSER_UT_H

#include <condition_variable>
#include <iremote_broker.h>
#include <mutex>
#include <vector>

#include "v1_2/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_2/include/idisplay_composer_interface.h"
#include "display_test_utils.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_2;

class DeathTest : public ::testing::Test {
public:
    sptr<Composer::V1_2::IDisplayComposerInterface> displayComposer_;
};
} // namespace SYSTEMTEST
} // namespace Display
} // namespace HDI
} // namespace OHOS

namespace OHOS {
class ComposerDiedRecipient : public IRemoteObject::DeathRecipient {
public:
    ComposerDiedRecipient() = default;
    virtual ~ComposerDiedRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
};
}
#endif // HDI_DEVICE_SYSTEM_TEST_H