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

class MyCallback : public HdiZCallback {
public:
    MyCallback() {}
    virtual ~MyCallback() = default;

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

class ZCodecHdiEdgeTest : public testing::TestWithParam<bool> {
public:
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }

    void SetUp()
    {
        bool isPassthrough = GetParam();
        fac = HdiZFactory::Get(isPassthrough);
        ASSERT_TRUE(fac != nullptr);
        zcb = sptr<MyCallback>::MakeSptr();
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
    int32_t StandardStart(sptr<HdiZComponent>& instance, int32_t width = 1280, int32_t height = 720);
    static sptr<HdiZFactory> fac;
    sptr<HdiZComponent> instance;
    sptr<HdiZCallback> zcb;
    static constexpr int32_t width = 1280;
    static constexpr int32_t height = 720;
};

sptr<HdiZFactory> ZCodecHdiEdgeTest::fac = nullptr;

int32_t ZCodecHdiEdgeTest::CreateZCodecByType(CodecType type, sptr<HdiZComponent>& instance)
{
    string name;
    if (type == CodecType::H264) {
        name = "z.hisi.video.encoder.avc";
    } else if (type == CodecType::H265) {
        name = "z.hisi.video.encoder.hevc";
    }
    sptr<ParcelableParam> param = nullptr;
    int32_t ret = fac->CreateByName(name, zcb, param, instance);
    return ret;
}

int32_t ZCodecHdiEdgeTest::StandardStart(sptr<HdiZComponent>& instance, int32_t w, int32_t h)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {w, h};
    param->Set(KEY_RESOLUTION, reso);
    int32_t ret = instance->SetParam(param);
    if (ret != 0) {
        return ret;
    }
    return instance->Start();
    }
    
/**
 * @tc.name: ZCodecHdiEdgeTest_CreateByName_InvalidName_001
 * @tc.desc: try to create zcodec instance with invalid component name
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_CreateByName_InvalidName_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName("invalid.component.name", zcb, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_CreateByName_EmptyName_001
 * @tc.desc: try to create zcodec instance with empty component name
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_CreateByName_EmptyName_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName("", zcb, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_CreateByName_NullCallback_001
 * @tc.desc: try to create zcodec instance with null callback
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_CreateByName_NullCallback_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByName("z.hisi.video.encoder.avc", nullptr, param, instance);
    ASSERT_TRUE(instance == nullptr && ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_NullParam_001
 * @tc.desc: try to SetParam with null parameter
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_NullParam_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->SetParam(nullptr);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_ZeroResolution_001
 * @tc.desc: try to SetParam with zero resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_ZeroResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {0, 0};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);  // 零分辨率应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_NegativeResolution_001
 * @tc.desc: try to SetParam with negative resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_NegativeResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {-1, -1};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);  // 负分辨率应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_OverflowResolution_001
 * @tc.desc: try to SetParam with overflow resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_OverflowResolution_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {INT_MAX, INT_MAX};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);  // 超大分辨率应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_InvalidKey_001
 * @tc.desc: try to SetParam with invalid key
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_InvalidKey_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set("invalid_key", 123);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);  // 无效键应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_SetParam_EmptyKey_001
 * @tc.desc: try to SetParam with empty key
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_SetParam_EmptyKey_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set("", 123);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret != 0);  // 空键应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_GetParam_EmptyKeys_001
 * @tc.desc: try to GetParam with empty keys
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_GetParam_EmptyKeys_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys;
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_GetParam_InvalidKey_001
 * @tc.desc: try to GetParam with invalid key
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_GetParam_InvalidKey_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {"invalid_key"};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_Start_Continuous_001
 * @tc.desc: try to start continuously without stop
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_Start_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    // 重复Start应该失败
    ret = instance->Start();
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_Stop_Continuous_001
 * @tc.desc: try to stop continuously
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_Stop_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);

    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_Flush_Continuous_001
 * @tc.desc: try to flush continuously after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_Flush_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    // 连续调用Flush多次
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_Start_Flush_Stop_Continuous_001
 * @tc.desc: try to Start_Flush_Stop_Start_Flush_Stop continuously
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_Start_Flush_Stop_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 第一次 Start->Flush->Stop
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);

    // 第二次 Start->Flush->Stop
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_BindImageBuffer_ZeroSize_001
 * @tc.desc: try to BindImageBuffer with zero size
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_BindImageBuffer_ZeroSize_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    HdiBufferAllocInfo info {
        true, 0, 0, 0,  // 零尺寸
        GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret != 0);  // 零尺寸应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_BindImageBuffer_NegativeSize_001
 * @tc.desc: try to BindImageBuffer with negative size
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_BindImageBuffer_NegativeSize_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    HdiBufferAllocInfo info {
        true, 0, -1, -1,  // 负尺寸
        GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret != 0);  // 负尺寸应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_BindImageBuffer_InvalidFormat_001
 * @tc.desc: try to BindImageBuffer with invalid pixel format
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_BindImageBuffer_InvalidFormat_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    HdiBufferAllocInfo info {
        true, 0, width, height,
        -1,  // 无效像素格式
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret != 0);  // 无效像素格式应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_UnbindImageBuffers_EmptyIds_001
 * @tc.desc: try to UnbindImageBuffers with empty ids
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_UnbindImageBuffers_EmptyIds_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    const vector<uint64_t> emptyIds;
    ret = instance->UnbindBuffers(emptyIds);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_UnbindImageBuffers_InvalidId_001
 * @tc.desc: try to UnbindImageBuffers with invalid id
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_UnbindImageBuffers_InvalidId_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    const vector<uint64_t> invalidIds {UINT_MAX};  // 无效ID
    ret = instance->UnbindBuffers(invalidIds);
    ASSERT_TRUE(ret != 0);  // 无效ID应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_QueueImageBuffers_EmptyInfos_001
 * @tc.desc: try to QueueImageBuffers with empty infos
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_QueueImageBuffers_EmptyInfos_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    vector<HdiZBufferInfo> emptyInfos;
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(emptyInfos, errCodes);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiEdgeTest_QueueImageBuffers_InvalidId_001
 * @tc.desc: try to QueueImageBuffers with invalid buffer id
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_QueueImageBuffers_InvalidId_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    vector<HdiZBufferInfo> infos;
    infos.push_back(HdiZBufferInfo {
        .id = UINT_MAX,  // 无效ID
        .offset = 0,
        .filledLen = 1024,
        .pts = 0,
        .flag = 0,
        .alongParam = ParcelableParam::Create()
    });
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret != 0);  // 无效ID应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_QueueImageBuffers_NegativeFilledLen_001
 * @tc.desc: try to QueueImageBuffers with negative filled length
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_QueueImageBuffers_NegativeFilledLen_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    vector<HdiZBufferInfo> infos;
    infos.push_back(HdiZBufferInfo {
        .id = 0,
        .offset = 0,
        .filledLen = -1,  // 负填充长度
        .pts = 0,
        .flag = 0,
        .alongParam = ParcelableParam::Create()
    });
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret != 0);  // 负填充长度应该失败
}

/**
 * @tc.name: ZCodecHdiEdgeTest_QueueImageBuffers_OverflowFilledLen_001
 * @tc.desc: try to QueueImageBuffers with overflow filled length
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEdgeTest, ZCodecHdiEdgeTest_QueueImageBuffers_OverflowFilledLen_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数并启动
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    vector<HdiZBufferInfo> infos;
    infos.push_back(HdiZBufferInfo {
        .id = 0,
        .offset = 0,
        .filledLen = UINT_MAX,  // 溢出填充长度
        .pts = 0,
        .flag = 0,
        .alongParam = ParcelableParam::Create()
    });
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret != 0);  // 溢出填充长度应该失败
}

INSTANTIATE_TEST_SUITE_P(
    ZCodecHdiEdgeFuncTest,
    ZCodecHdiEdgeTest,
    testing::Values(false, true));

}  // namespace