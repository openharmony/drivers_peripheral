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

#include <climits>
#include <gtest/gtest.h>

#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v1_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;
namespace {
class HdfAudioUtManagerServiceTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void HdfAudioUtManagerServiceTest::SetUp()
{
}

void HdfAudioUtManagerServiceTest::TearDown()
{
}
// only for test
HWTEST_F(HdfAudioUtManagerServiceTest, HdfAudioManagerReleaseAudioManagerObjectIsValid001, TestSize.Level1)
{
    struct IAudioManager *manager = nullptr;
    manager = IAudioManagerGet(false);
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(HDF_SUCCESS, manager->ReleaseAudioManagerObject(manager));
}
}