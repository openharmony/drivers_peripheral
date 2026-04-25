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

#include <chrono>
#include <cinttypes>
#include <gtest/gtest.h>
#include <gtest/gtest-param-test.h>
#include <list>
#include <map>
#include <thread>
#include "error_type.h"
#include "key_value.h"
#include "codec_log_wrapper.h"
#include "surface_buffer.h"
#include "v1_0/hdi_z_factory.h"

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

class ZCodecHdiDecTest : public testing::TestWithParam<bool> {
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

sptr<HdiZFactory> ZCodecHdiDecTest::fac = nullptr;

int32_t ZCodecHdiDecTest::CreateZCodecByType(CodecType type, sptr<HdiZComponent>& instance)
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
 * @tc.name: ZCodecHdiDecTest_CreateByStandard_001
 * @tc.desc: try to create zcodec decoder instance by standard AVC
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_CreateByStandard_001, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByStandard(OHOS::HDI::Codec::Zcodec::V1_0::Standard::AVC, false, zcb, param, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_CreateByStandard_002
 * @tc.desc: try to create zcodec decoder instance by standard HEVC
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_CreateByStandard_002, TestSize.Level1)
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    int32_t ret = fac->CreateByStandard(OHOS::HDI::Codec::Zcodec::V1_0::Standard::HEVC, false, zcb, param, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_CreateByName_001
 * @tc.desc: try to create zcodec decoder instance by z.hisi.video.decoder.avc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_CreateByName_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_CreateByName_002
 * @tc.desc: try to create zcodec decoder instance by z.hisi.video.decoder.hevc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_CreateByName_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_001
 * @tc.desc: try to start avc decoder instance without resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret != 0);  // Start前必须设置分辨率，否则应该失败
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_002
 * @tc.desc: try to start hevc decoder instance without resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret != 0);  // Start前必须设置分辨率，否则应该失败
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_003
 * @tc.desc: try to start avc decoder instance with resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    ASSERT_TRUE(ret == 0);  // 设置分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_004
 * @tc.desc: try to start hevc decoder instance with resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_004, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    ASSERT_TRUE(ret == 0);  // 设置分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_005
 * @tc.desc: try to start avc decoder instance with different resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_005, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置不同的分辨率参数 (1920x1080)
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1920, 1080};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = 1920 * 1080 * 3 / 2,
    };
    HdiBufferWithId decBuf;
    ret = instance->BindBufferByAlloc(info, nullptr, decBuf);
    ASSERT_TRUE(ret == 0 && decBuf.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);  // 设置不同分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiDecTest_Stop_001
 * @tc.desc: try to stop avc decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Stop_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Stop_002
 * @tc.desc: try to stop hevc decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Stop_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Stop_003
 * @tc.desc: try to stop avc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Stop_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
}

/**
 * @tc.name: ZCodecHdiDecTest_Stop_004
 * @tc.desc: try to stop hevc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Stop_004, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
}

/**
 * @tc.name: ZCodecHdiDecTest_Flush_001
 * @tc.desc: try to flush avc decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Flush_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Flush();
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Flush_002
 * @tc.desc: try to flush hevc decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Flush_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Flush();
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Flush_003
 * @tc.desc: try to flush avc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Flush_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Flush_004
 * @tc.desc: try to flush hevc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Flush_004, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Start_Stop_Start_001
 * @tc.desc: try to Start_Stop_Start hevc decoder instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Start_Stop_Start_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 第一次启动：先设置分辨率参数
    sptr<ParcelableParam> param1 = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param1->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param1);
    ASSERT_TRUE(ret == 0);

    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info1 {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf1;
    ret = instance->BindBufferByAlloc(info1, nullptr, decBuf1);
    ASSERT_TRUE(ret == 0 && decBuf1.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);

    // 重启：再次设置分辨率参数
    sptr<ParcelableParam> param2 = ParcelableParam::Create();
    param2->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param2);
    ASSERT_TRUE(ret == 0);
    // 申请buffer（解码器start前必须先申请buffer）
    HdiBufferAllocInfo info2 {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId decBuf2;
    ret = instance->BindBufferByAlloc(info2, nullptr, decBuf2);
    ASSERT_TRUE(ret == 0 && decBuf2.buf != nullptr);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_001
 * @tc.desc: try to SetParam decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    Resolution resoOut {};
    paramOut->Get(KEY_RESOLUTION, resoOut);
    ASSERT_TRUE(resoOut.w == 1280 && resoOut.h == 720);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_002
 * @tc.desc: try to SetParam with key KEY_RESOLUTION to out-of-range value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {12800, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_003
 * @tc.desc: try to SetParam with key KEY_RESOLUTION to invalid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_RESOLUTION, 1280);
    ret = instance->SetParam(param);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_004
 * @tc.desc: try to SetParam with key KEY_HIGH_PERF_FLAG to valid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_004, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    bool expect = true;
    param->Set(KEY_HIGH_PERF_FLAG, expect);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // KEY_HIGH_PERF_FLAG不支持查询
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_HIGH_PERF_FLAG};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_005
 * @tc.desc: try to SetParam with key KEY_HIGH_PERF_FLAG to invalid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_005, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_HIGH_PERF_FLAG, 0);
    ret = instance->SetParam(param);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_006
 * @tc.desc: try to SetParam with key KEY_CALLER_NAME to valid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_006, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    std::string expect = "test_caller";
    param->Set(KEY_CALLER_NAME, expect);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_CALLER_NAME};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    std::string actural = "";
    ASSERT_TRUE(paramOut->Get(KEY_CALLER_NAME, actural));
    ASSERT_TRUE(actural == expect);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_007
 * @tc.desc: try to SetParam with key KEY_CALLER_NAME to invalid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_007, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_CALLER_NAME, 0);
    ret = instance->SetParam(param);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_008
 * @tc.desc: try to SetParam with key KEY_CONSUMER_USAGE to valid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_008, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    uint64_t expect = 1;
    param->Set(KEY_CONSUMER_USAGE, expect);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // KEY_CONSUMER_USAGE不支持查询
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_CONSUMER_USAGE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_009
 * @tc.desc: try to SetParam with key KEY_CONSUMER_USAGE to invalid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_009, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_CONSUMER_USAGE, 0);
    ret = instance->SetParam(param);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_010
 * @tc.desc: try to SetParam with key KEY_UV_ORDER to valid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_010, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_UV_ORDER, true);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_011
 * @tc.desc: try to SetParam with key KEY_UV_ORDER to valid value
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_011, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_UV_ORDER, false);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_013
 * @tc.desc: try to SetParam with partial success
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_013, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    std::string callerName = "test";
    param->Set(KEY_CALLER_NAME, callerName);
    param->Set(KEY_FRAME_RATE, 60);
    ret = instance->SetParam(param);
    ASSERT_EQ(ret, ErrorType::PARTIAL_SUCC);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_014
 * @tc.desc: try to SetParam with unsupported key
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_014, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_I_FRAME_INTERVAL, 60);
    ret = instance->SetParam(param);
    ASSERT_EQ(ret, ErrorType::ALL_FAIL);
}

/**
 * @tc.name: ZCodecHdiDecTest_GetParam_001
 * @tc.desc: try to GetParam decoder instance without SetParam
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_GetParam_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_FALSE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_GetParam_002
 * @tc.desc: try to GetParam decoder instance with SetParam
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_GetParam_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramIn = ParcelableParam::Create();
    Resolution resoIn {1280, 720};
    paramIn->Set(KEY_RESOLUTION, resoIn);
    ret = instance->SetParam(paramIn);
    ASSERT_TRUE(ret == 0);

    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    Resolution resoOut {};
    paramOut->Get(KEY_RESOLUTION, resoOut);
    ASSERT_TRUE(resoOut.w == resoIn.w && resoOut.h == resoIn.h);
}

/**
 * @tc.name: ZCodecHdiDecTest_GetParam_004
 * @tc.desc: try to GetParam with all fail
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_GetParam_004, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION, KEY_INPUT_STREAM_ERROR};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_EQ(ret, ErrorType::ALL_FAIL);
}

/**
 * @tc.name: ZCodecHdiDecTest_BindBufferByAlloc_001
 * @tc.desc: try to BindBufferByAlloc decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_BindBufferByAlloc_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);
}

/**
 * @tc.name: ZCodecHdiDecTest_BindBufferByAlloc_002
 * @tc.desc: try to BindBufferByAlloc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_BindBufferByAlloc_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    HdiBufferAllocInfo infoBefore {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId bufBefore;
    ret = instance->BindBufferByAlloc(infoBefore, nullptr, bufBefore);
    ASSERT_TRUE(ret == 0 && bufBefore.buf != nullptr);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    HdiBufferAllocInfo infoAfter {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId bufAfter;
    ret = instance->BindBufferByAlloc(infoAfter, nullptr, bufAfter);
    ASSERT_TRUE(ret != 0 || bufAfter.buf == nullptr); // start后不允许bind
}

/**
 * @tc.name: ZCodecHdiDecTest_BindBufferByAlloc_003
 * @tc.desc: try to BindBufferByAlloc for decoder output buffer
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_BindBufferByAlloc_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 解码器输出缓冲区
    HdiBufferAllocInfo info {
        .isImage = false,
        .capacity = width * height * 3 / 2,
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);
}

/**
 * @tc.name: ZCodecHdiDecTest_UnbindBuffers_001
 * @tc.desc: try to UnbindBuffers decoder instance without start and bind
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_UnbindBuffers_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    const vector<uint64_t> ids {0};
    ret = instance->UnbindBuffers(ids);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_UnbindBuffers_002
 * @tc.desc: try to UnbindBuffers decoder instance after start without bind
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_UnbindBuffers_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    const vector<uint64_t> ids {0};
    ret = instance->UnbindBuffers(ids);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_QueueInputBuffers_001
 * @tc.desc: try to QueueInputBuffers decoder instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_QueueInputBuffers_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    vector<HdiZBufferInfo> infos;
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_QueueInputBuffers_002
 * @tc.desc: try to QueueInputBuffers decoder instance after start with BindBufferByAlloc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_QueueInputBuffers_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
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
    infos.push_back(HdiZBufferInfo {.id = decBuf.id });
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_GetCapability_001
 * @tc.desc: try to GetCapability decoder instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_GetCapability_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    HdiCapability cap;
    ret = instance->GetCapability(cap);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_FrameRate_BeforeStart_001
 * @tc.desc: try to SetParam with KEY_FRAME_RATE (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_FrameRate_BeforeStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    uint32_t targetFrameRate = 60;
    param->Set(KEY_FRAME_RATE, targetFrameRate);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_FRAME_RATE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t frameRate {};
    ASSERT_TRUE(paramOut->Get(KEY_FRAME_RATE, frameRate));
    ASSERT_TRUE(frameRate == targetFrameRate);
}

/**
 * @tc.name: ZCodecHdiDecTest_SetParam_FrameRate_AfterStart_001
 * @tc.desc: try to SetParam with KEY_FRAME_RATE after start (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_SetParam_FrameRate_AfterStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param1 = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param1->Set(KEY_RESOLUTION, reso);
    uint32_t frameRate = 30;
    param1->Set(KEY_FRAME_RATE, frameRate);
    ret = instance->SetParam(param1);
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

    sptr<ParcelableParam> param2 = ParcelableParam::Create();
    frameRate = 60;
    param2->Set(KEY_FRAME_RATE, frameRate);
    ret = instance->SetParam(param2);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_GetCapabilities_001
 * @tc.desc: try to GetCapabilities from factory
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_GetCapabilities_001, TestSize.Level1)
{
    vector<HdiCapability> caps;
    int32_t ret = fac->GetCapabilities(caps);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(caps.size() == 0);
}

/**
 * @tc.name: ZCodecHdiDecTest_Pause_001
 * @tc.desc: try to Pause avc decoder instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Pause_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
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

    sptr<ParcelableParam> pauseParam = ParcelableParam::Create();
    pauseParam->Set(KEY_OPERATING_RATE, 30);
    ret = instance->Pause(pauseParam);
    ASSERT_TRUE(ret != 0);  // 解码器暂时不支持pause操作
}

/**
 * @tc.name: ZCodecHdiDecTest_Pause_002
 * @tc.desc: try to Pause hevc decoder with null param
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_Pause_002, TestSize.Level1)
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

    ret = instance->Pause(nullptr);
    ASSERT_TRUE(ret != 0);  // 解码器暂时不支持pause操作
}

/**
 * @tc.name: ZCodecHdiDecTest_BindBufferByUse_001
 * @tc.desc: try to BindBufferByUse with null buffer
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiDecTest, ZCodecHdiDecTest_BindBufferByUse_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    uint64_t bufId;
    ret = instance->BindBufferByUse(nullptr, nullptr, bufId);
    ASSERT_TRUE(ret != 0);
}

INSTANTIATE_TEST_SUITE_P(
    ZCodecHdiDecFuncTest,
    ZCodecHdiDecTest,
    testing::Values(false, true));

}  // namespace