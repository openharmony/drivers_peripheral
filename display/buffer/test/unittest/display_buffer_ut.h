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

#ifndef DISPLAY_BUFFER_UT_H
#define DISPLAY_BUFFER_UT_H
#include "gtest/gtest.h"
#include "v1_0/iallocator.h"
#include "v1_0/imapper.h"
#include "v1_1/imetadata.h"
#include "v1_0/display_buffer_type.h"
#include "v1_3/include/idisplay_buffer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using OHOS::HDI::Display::Buffer::V1_0::IAllocator;
using OHOS::HDI::Display::Buffer::V1_0::IMapper;
using OHOS::HDI::Display::Buffer::V1_0::AllocInfo;
using OHOS::HDI::Display::Buffer::V1_1::IMetadata;
using OHOS::HDI::Display::Buffer::V1_3::IDisplayBuffer;

class DisplayBufferUt : public ::testing::TestWithParam<AllocInfo> {
protected:
    virtual void SetUp();
    virtual void TearDown();
public:
    IDisplayBuffer* displayBuffer_{ nullptr };
    int32_t AllocMemTest(AllocInfo& info);
    int32_t PassthroughTest(AllocInfo& info);
    void MetadataTest(BufferHandle& handle);
};
} // OHOS
} // HDI
} // DISPLAY
} // TEST
#endif // DISPLAY_BUFFER_UT_H