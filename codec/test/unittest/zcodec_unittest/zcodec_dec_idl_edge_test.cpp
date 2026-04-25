/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gtest/gtest-param-test.h>
#include <list>
#include <chrono>
#include <thread>
#include <map>
#include <cinttypes>
#include <climits>
#include "surface_buffer.h"
#include "v1_0/hdi_z_factory.h"
#include "key_value.h"
#include "codec_log_wrapper.h"

#define ERR_COUNT (-1)

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace std::chrono_literals;
using namespace OHOS::HDI::Codec;
using namespace OHOS::HDI::Codec::Zcodec::V1_0;
using ZBufferId = uint32_t;

namespace Vendor::ZCodec {

enum class CodecType {
    H264,
    H265
};

class MyDecCallback : public HdiZCallback {
public:
    MyDecCallback() {}
    virtual ~MyDecCallback() = default;

    int32_t OnEvent(int32_t event, const sptr<ParcelableParam>& param) override { return 0; }
    int32_t OnBuffersBinded(const std::vector<HdiBufferWithId>& bufs) override {return 0;}
    int32_t OnBuffersUnbinded(const std::vector<uint64_t>& ids) override {return 0;}
    int32_t OnInputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override
    {
        CODEC_LOGI("OnInputBuffersDone");
        return 0;
    }
    int32_t OnOutputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override {return 0;}
};

class ZCodecHdiDecEdgeTest : public testing::TestWithParam<bool> {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp()
    {
        bool isPassthrough = GetParam();
        fac = HdiZFactory::Get(isPassthrough);
        ASSERT_TRUE(fac != nullptr);
        zcb = sptr<MyDecCallback>::MakeSptr();
        ASSERT_TRUE(zcb != nullptr);
    }

    void TearDown()
    {
        zcb = nullptr;
        instance = nullptr;
        fac = nullptr;
    }

public:
    int32_t CreateZCodecByType(CodecType type, sptr<HdiZComponent>& instance);
    static sptr<HdiZFactory> fac;
    sptr<HdiZComponent> instance;
    sptr<HdiZCallback> zcb;
    static constexpr int32_t width = 1280;
    static constexpr int32_t height = 720;
};

sptr<HdiZFactory> ZCodecHdiDecEdgeTest::fac = nullptr;

int32_t ZCodecHdiDecEdgeTest::CreateZCodecByType(CodecType type, sptr<HdiZComponent>& instance)
{
    string name;
    if (type == CodecType::H264) {
        name = "z.hisi.video.decoder.avc";
    } else if (type == CodecType::H265) {
        name = "z.hisi.video.decoder.hevc";
    }
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName(name, zcb, param, instance);
    return ret;
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_CreateByStandard_InvalidStandard_001
 * @tc.desc: create decoder with invalid standard
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_CreateByStandard_InvalidStandard_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByStandard(static_cast<OHOS::HDI::Codec::Zcodec::V1_0::Standard>(999), false, zcb, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_CreateByName_InvalidName_001
 * @tc.desc: create decoder with invalid name
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_CreateByName_InvalidName_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName("invalid.decoder.name", zcb, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_CreateByName_EmptyName_001
 * @tc.desc: create decoder with empty name
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_CreateByName_EmptyName_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName("", zcb, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_CreateByStandard_NullCallback_001
 * @tc.desc: create decoder with null callback
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_CreateByStandard_NullCallback_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByStandard(Standard::AVC, false, nullptr, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_SetParam_NullParam_001
 * @tc.desc: SetParam with null parameter
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_SetParam_NullParam_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->SetParam(nullptr);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_SetParam_ZeroResolution_001
 * @tc.desc: SetParam with zero resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_SetParam_ZeroResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {0, 0};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_SetParam_NegativeResolution_001
 * @tc.desc: SetParam with negative resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_SetParam_NegativeResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {-1, -1};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_SetParam_OverflowResolution_001
 * @tc.desc: SetParam with overflow resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_SetParam_OverflowResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {INT_MAX, INT_MAX};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_SetParam_InvalidKey_001
 * @tc.desc: SetParam with invalid key
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_SetParam_InvalidKey_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set("invalid_key", 123);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_Start_Continuous_001
 * @tc.desc: start decoder continuously
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_Start_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_Stop_Continuous_001
 * @tc.desc: stop decoder continuously
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_Stop_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_BindBuffer_ZeroSize_001
 * @tc.desc: BindBuffer with zero size
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_BindBuffer_ZeroSize_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    HdiBufferAllocInfo info {
        .isImage = true,
        .capacity = 0,
        .width = 0,
        .height = 0,
        .format = GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_BindBuffer_InvalidFormat_001
 * @tc.desc: BindBuffer with invalid pixel format
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_BindBuffer_InvalidFormat_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    HdiBufferAllocInfo info {
        .isImage = true,
        .capacity = width * height * 3 / 2,
        .width = width,
        .height = height,
        .format = -1,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_UnbindBuffers_EmptyIds_001
 * @tc.desc: UnbindBuffers with empty ids
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_UnbindBuffers_EmptyIds_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    const vector<uint64_t> emptyIds;
    ret = instance->UnbindBuffers(emptyIds);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_UnbindBuffers_InvalidId_001
 * @tc.desc: UnbindBuffers with invalid id
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_UnbindBuffers_InvalidId_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    const vector<uint64_t> invalidIds {UINT_MAX};
    ret = instance->UnbindBuffers(invalidIds);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_QueueInputBuffers_EmptyInfos_001
 * @tc.desc: QueueInputBuffers with empty infos
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_QueueInputBuffers_EmptyInfos_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    vector<HdiZBufferInfo> emptyInfos;
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(emptyInfos, errCodes);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_QueueInputBuffers_InvalidId_001
 * @tc.desc: QueueInputBuffers with invalid buffer id
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_QueueInputBuffers_InvalidId_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    vector<HdiZBufferInfo> infos;
    infos.push_back(HdiZBufferInfo {.id = UINT_MAX, .offset = 0, .filledLen = 1024, .pts = 0, .flag = 0, .alongParam = ParcelableParam::Create()});
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecEdgeTest_QueueOutputBuffers_EmptyInfos_001
 * @tc.desc: QueueOutputBuffers with empty infos
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecEdgeTest, ZCodecHdiDecEdgeTest_QueueOutputBuffers_EmptyInfos_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    vector<HdiZBufferInfo> emptyInfos;
    vector<int32_t> errCodes;
    ret = instance->QueueOutputBuffers(emptyInfos, errCodes);
    ASSERT_TRUE(ret != 0);
}

INSTANTIATE_TEST_SUITE_P(
    ZCodecHdiDecEdgeFuncTest,
    ZCodecHdiDecEdgeTest,
    testing::Values(false, true));

}  // namespace
