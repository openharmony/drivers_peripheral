/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "daudio_manager_interface_impl_test.h"

using namespace testing::ext;

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V2_1 {
void DAudioManagerInterfaceImplTest::SetUpTestCase(void) {}

void DAudioManagerInterfaceImplTest::TearDownTestCase(void) {}

void DAudioManagerInterfaceImplTest::SetUp(void)
{
    callbackObj_ = sptr<IDAudioCallback>(new MockIDAudioCallback);
}

void DAudioManagerInterfaceImplTest::TearDown(void) {}

/**
 * @tc.name: RegisterAudioDevice_001
 * @tc.desc: Verify the RegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, RegisterAudioDevice_001, TestSize.Level1)
{
    std::string adpName;
    std::string capability;
    int32_t devId = 11;
    EXPECT_NE(HDF_SUCCESS,
        DAudioManagerInterfaceImpl::GetDAudioManager()->RegisterAudioDevice(adpName, devId, capability, callbackObj_));
    EXPECT_NE(HDF_SUCCESS, DAudioManagerInterfaceImpl::GetDAudioManager()->UnRegisterAudioDevice(adpName, devId));
}

/**
 * @tc.name: RegisterAudioDevice_002
 * @tc.desc: Verify the RegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, RegisterAudioDevice_002, TestSize.Level1)
{
    std::string adpName = "hello";
    std::string capability = "world";
    int32_t devId = 64;
    EXPECT_NE(HDF_SUCCESS,
        DAudioManagerInterfaceImpl::GetDAudioManager()->RegisterAudioDevice(adpName, devId, capability, callbackObj_));
    EXPECT_NE(HDF_SUCCESS, DAudioManagerInterfaceImpl::GetDAudioManager()->UnRegisterAudioDevice(adpName, devId));
}

/**
 * @tc.name: UnRegisterAudioDevice_001
 * @tc.desc: Verify the UnRegisterAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, UnRegisterAudioDevice_001, TestSize.Level1)
{
    std::string unadpName;
    int32_t devId = 11;
    EXPECT_NE(HDF_SUCCESS, DAudioManagerInterfaceImpl::GetDAudioManager()->UnRegisterAudioDevice(unadpName, devId));
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, NotifyEvent_001, TestSize.Level1)
{
    std::string adpName = "hello";
    int32_t devId = 11;
    int32_t streamId = 0;
    DAudioEvent event;
    EXPECT_EQ(HDF_FAILURE, DAudioManagerInterfaceImpl::GetDAudioManager()->NotifyEvent(adpName,
        devId, streamId, event));
}

/**
 * @tc.name: NotifyEvent_002
 * @tc.desc: Verify the NotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, NotifyEvent_002, TestSize.Level1)
{
    std::string adpName = "hello";
    int32_t devId = 64;
    int32_t streamId = 0;
    DAudioEvent event;
    event.type = 15;
    event.content = "hello_world";
    EXPECT_NE(HDF_SUCCESS, DAudioManagerInterfaceImpl::GetDAudioManager()->NotifyEvent(adpName,
        devId, streamId, event));
}

/**
 * @tc.name: UnRegisterAudioHdfListener_001
 * @tc.desc: Verify the UnRegisterAudioHdfListener function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6G
 */
HWTEST_F(DAudioManagerInterfaceImplTest, UnRegisterAudioHdfListener_001, TestSize.Level1)
{
    std::string adpName = "hello";
    EXPECT_EQ(HDF_FAILURE,
        DAudioManagerInterfaceImpl::GetDAudioManager()->UnRegisterAudioHdfListener(adpName));
    auto audioMgr = DAudioManagerInterfaceImpl::GetDAudioManager()->audioMgr_;
    DAudioManagerInterfaceImpl::GetDAudioManager()->audioMgr_ = nullptr;
    auto ret = DAudioManagerInterfaceImpl::GetDAudioManager()->UnRegisterAudioHdfListener(adpName);
    DAudioManagerInterfaceImpl::GetDAudioManager()->audioMgr_ = audioMgr;
    EXPECT_EQ(HDF_FAILURE, ret);
}
} // V2_1
} // AudioExt
} // Daudio
} // HDI
} // OHOS
