/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <hdf_log.h>
#include "../../../chip/hdi_service/iface_tool.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V2_0;

namespace IfaceToolTest {
class IfaceToolTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetWifiUpStateTest
 * @tc.desc: SetWifiUpState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IfaceToolTest, SetWifiUpStateTest, TestSize.Level1)
{
    HDF_LOGI("SetWifiUpStateTest started");
    std::shared_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    bool requestUp = true;
    EXPECT_TRUE(ifaceTool->SetWifiUpState(requestUp));
    requestUp = false;
    EXPECT_TRUE(ifaceTool->SetWifiUpState(requestUp));
}
}