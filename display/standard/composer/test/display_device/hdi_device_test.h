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

#ifndef HDI_DEVICE_TEST_H
#define HDI_DEVICE_TEST_H
#include <condition_variable>
#include <vector>
#include <mutex>
#include "gtest/gtest.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "display_test_utils.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

class DeviceLayerDisplay : public ::testing::TestWithParam<std::vector<LayerSettings>> {
protected:
    void SetUp() {}
    void TearDown();
};

class DeviceTest : public ::testing::Test {
protected:
    void TearDown();
};

// only support single layer test
class LayerRotateTest : public ::testing::TestWithParam<LayerSettings> {
protected:
    void TearDown();
};

class VblankTest : public ::testing::Test {
protected:
    void TearDown();
};

class VblankCtr {
public:
    static VblankCtr &GetInstance()
    {
        static VblankCtr instance;
        return instance;
    }
    void NotifyVblank(unsigned int sequence, uint64_t ns, void *data);
    int32_t WaitVblank(uint32_t ms);

protected:
    void TearDown();

private:
    std::mutex mVblankMutex;
    std::condition_variable mVblankCondition;
    VblankCtr() {}
    ~VblankCtr();
    bool mHasVblank = false;
};
} // OHOS
} // HDI
} // Display
} // TEST

#endif // HDI_DEVICE_TEST_H
