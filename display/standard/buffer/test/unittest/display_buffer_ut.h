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

#ifndef DISPLAY_BUFFER_UT_H
#define DISPLAY_BUFFER_UT_H
#include "gtest/gtest.h"
#include "v1_0/iallocator.h"
#include "v1_0/imapper.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

using OHOS::HDI::Display::Buffer::V1_0::IAllocator;
using OHOS::HDI::Display::Buffer::V1_0::IMapper;
using OHOS::HDI::Display::Buffer::V1_0::AllocInfo;
using OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer;

namespace {
struct AllocTestPrms {
    AllocInfo allocInfo;
    int32_t expectStride;
    int32_t expectSize;
};

class DisplayBufferUt : public ::testing::TestWithParam<AllocTestPrms> {
protected:
    virtual void SetUp();
    virtual void TearDown();
public:
    IDisplayBuffer* displayBuffer_{ nullptr };
    int32_t AllocMemTest(AllocTestPrms &info);
};
}
#endif // DISPLAY_BUFFER_UT_H
