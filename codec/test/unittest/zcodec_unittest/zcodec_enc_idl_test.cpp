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
#include "surface_buffer.h"
#include "v1_0/hdi_z_factory.h"
#include "key_value.h"
#include "codec_log_wrapper.h"

namespace Vendor::ZCodec {

#define ERR_COUNT (-1)

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace std::chrono_literals;
using namespace OHOS::HDI::Codec;
using namespace OHOS::HDI::Codec::Zcodec::V1_0;
using ZBufferId = uint32_t;

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

class ZCodecHdiEncTest : public testing::TestWithParam<bool> {
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
    static sptr<HdiZFactory> fac;
    sptr<HdiZComponent> instance;
    sptr<HdiZCallback> zcb;
    static constexpr int32_t width = 1280;
    static constexpr int32_t height = 720;
};

sptr<HdiZFactory> ZCodecHdiEncTest::fac = nullptr;

int32_t ZCodecHdiEncTest::CreateZCodecByType(CodecType type, sptr<HdiZComponent>& instance)
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

/**
 * @tc.name: ZCodecHdiTest_CreateByName_001
 * @tc.desc: try to create zcodec instance by z.hisi.video.encoder.avc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_CreateByName_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_CreateByName_002
 * @tc.desc: try to create zcodec instance by z.hisi.video.encoder.avc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_CreateByName_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_Start_001
 * @tc.desc: try to start avc zcodec instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret != 0);  // Start前必须设置分辨率，否则应该失败
}

/**
 * @tc.name: ZCodecHdiTest_Start_002
 * @tc.desc: try to start hevc zcodec instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret != 0);  // Start前必须设置分辨率，否则应该失败
}

/**
 * @tc.name: ZCodecHdiTest_Start_003
 * @tc.desc: try to start avc zcodec instance with resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);  // 设置分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiTest_Start_004
 * @tc.desc: try to start hevc zcodec instance with resolution set
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_004, TestSize.Level1)
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
    ASSERT_TRUE(ret == 0);  // 设置分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiTest_Start_005
 * @tc.desc: try to start avc zcodec instance with different resolution
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_005, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置不同的分辨率参数 (1920x1080)
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1920, 1080};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);  // 设置不同分辨率后应该可以成功启动
}

/**
 * @tc.name: ZCodecHdiTest_Stop_001
 * @tc.desc: try to stop avc zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Stop_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: ZCodecHdiTest_Stop_002
 * @tc.desc: try to stop hevc zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Stop_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Stop();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: ZCodecHdiTest_Stop_003
 * @tc.desc: try to stop avc zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Stop_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
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
}

/**
 * @tc.name: ZCodecHdiTest_Stop_002
 * @tc.desc: try to stop hevc zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Stop_004, TestSize.Level1)
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
}

/**
 * @tc.name: ZCodecHdiTest_Flush_001
 * @tc.desc: try to flush avc zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Flush();
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiTest_Flush_002
 * @tc.desc: try to start hevc zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    ret = instance->Flush();
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiTest_Flush_003
 * @tc.desc: try to flush avc zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_003, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_Flush_004
 * @tc.desc: try to flush hevc zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_004, TestSize.Level1)
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
    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_Flush_Continuous_001
 * @tc.desc: try to flush avc zcodec instance continuously after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_Continuous_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
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
 * @tc.name: ZCodecHdiTest_Flush_Continuous_002
 * @tc.desc: try to flush hevc zcodec instance continuously after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Flush_Continuous_002, TestSize.Level1)
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
 * @tc.name: ZCodecHdiTest_Start_Flush_Stop_001
 * @tc.desc: try to Start_Flush_Stop avc zcodec instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_Flush_Stop_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    // 先设置分辨率参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);

    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_Start_Flush_Stop_002
 * @tc.desc: try to Start_Flush_Stop hevc zcodec instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_Flush_Stop_002, TestSize.Level1)
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

    ret = instance->Flush();
    ASSERT_TRUE(ret == 0);

    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_Start_Stop_Flush_001
 * @tc.desc: try to Start_Stop_Start hevc zcodec instance
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_Start_Stop_Start_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    
    // 第一次启动：先设置分辨率参数
    sptr<ParcelableParam> param1 = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param1->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param1);
    ASSERT_TRUE(ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    
    ret = instance->Stop();
    ASSERT_TRUE(ret == 0);
    
    // 重启：再次设置分辨率参数
    sptr<ParcelableParam> param2 = ParcelableParam::Create();
    param2->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param2);
    ASSERT_TRUE(ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_001
 * @tc.desc: try to SetParam zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_001, TestSize.Level1)
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
 * @tc.name: ZCodecHdiTest_SetParam_002
 * @tc.desc: try to SetParam zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param1 = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param1->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param1);
    ASSERT_TRUE(ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    sptr<ParcelableParam> param2 = ParcelableParam::Create();
    reso = {1920, 1080};
    param2->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param2);
    ASSERT_TRUE(ret != 0);  // 暂不支持动态分辨率，第二次设置失败

    // 验证参数仍然为第一次设置的值
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    Resolution resoOut {};
    paramOut->Get(KEY_RESOLUTION, resoOut);
    ASSERT_TRUE(resoOut.w == 1280 && resoOut.h == 720);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_Profile_001
 * @tc.desc: try to SetParam with KEY_PROFILE (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_Profile_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_PROFILE, AvcProfile::AVC_PROFILE_HIGH);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_PROFILE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    AvcProfile profile {};
    paramOut->Get(KEY_PROFILE, profile);
    ASSERT_TRUE(profile == AvcProfile::AVC_PROFILE_HIGH);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_Profile_002
 * @tc.desc: try to SetParam with KEY_PROFILE (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_Profile_002, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_PROFILE, static_cast<uint32_t>(HevcProfile::HEVC_PROFILE_MAIN_10));
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_PROFILE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t profile {};
    paramOut->Get(KEY_PROFILE, profile);
    ASSERT_TRUE(profile == static_cast<uint32_t>(HevcProfile::HEVC_PROFILE_MAIN_10));
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_I_FRAME_INTERVAL_001
 * @tc.desc: try to SetParam with KEY_I_FRAME_INTERVAL (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_I_FRAME_INTERVAL_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_I_FRAME_INTERVAL, 1000);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_I_FRAME_INTERVAL};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    int32_t interval {};
    paramOut->Get(KEY_I_FRAME_INTERVAL, interval);
    ASSERT_TRUE(interval == 1000);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_requestIDR_001
 * @tc.desc: try to SetParam with boolean KEY_REQUEST_IDR (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_requestIDR_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    sptr<ParcelableParam> paramIn = ParcelableParam::Create();
    paramIn->Set(KEY_REQUEST_IDR, true);
    ret = instance->SetParam(paramIn);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_BitrateControlMode_001
 * @tc.desc: try to SetParam with KEY_BITRATE_CONTROL_MODE (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_BitrateControlMode_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_BITRATE_CONTROL_MODE, static_cast<uint32_t>(BitrateControlMode::CBR));
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_BITRATE_CONTROL_MODE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t mode {};
    paramOut->Get(KEY_BITRATE_CONTROL_MODE, mode);
    ASSERT_TRUE(mode == static_cast<uint32_t>(BitrateControlMode::CBR));
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_TargetBitrate_001
 * @tc.desc: try to SetParam with KEY_TARGET_BITRATE (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_TargetBitrate_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_TARGET_BITRATE, static_cast<uint32_t>(5000000));  // 5Mbps
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_TARGET_BITRATE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t bitrate {};
    paramOut->Get(KEY_TARGET_BITRATE, bitrate);
    ASSERT_TRUE(bitrate == 5000000);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_TargetQuality_001
 * @tc.desc: try to SetParam with KEY_TARGET_QUALITY (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_TargetQuality_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_TARGET_QUALITY, static_cast<uint32_t>(90));
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_TARGET_QUALITY};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t quality {};
    paramOut->Get(KEY_TARGET_QUALITY, quality);
    ASSERT_TRUE(quality != 0);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_TargetQP_001
 * @tc.desc: try to SetParam with KEY_TARGET_QP (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_TargetQP_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_TARGET_QP, 28);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_TARGET_QP};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    int32_t qp {};
    paramOut->Get(KEY_TARGET_QP, qp);
    ASSERT_TRUE(qp == 28);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_ColorAspects_001
 * @tc.desc: try to SetParam with KEY_COLOR_ASPECTS (start前支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_ColorAspects_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    ColorAspects aspects {
        .range = true,
        .primaries = 1,
        .transfer = 1,
        .matrixCoeffs = 1
    };
    param->Set(KEY_COLOR_ASPECTS, aspects);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_COLOR_ASPECTS};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    ColorAspects aspectsOut {};
    paramOut->Get(KEY_COLOR_ASPECTS, aspectsOut);
    ASSERT_TRUE(aspectsOut.range == aspects.range &&
                aspectsOut.primaries == aspects.primaries &&
                aspectsOut.transfer == aspects.transfer &&
                aspectsOut.matrixCoeffs == aspects.matrixCoeffs);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_FrameRate_BeforeStart_001
 * @tc.desc: try to SetParam with KEY_FRAME_RATE (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_FrameRate_BeforeStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    uint32_t framerate = 60;
    param->Set(KEY_FRAME_RATE, framerate);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    // 验证参数设置成功
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_FRAME_RATE};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret == 0);
    uint32_t frameRate {};
    paramOut->Get(KEY_FRAME_RATE, frameRate);
    ASSERT_TRUE(frameRate == 60);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_FrameRate_AfterStart_001
 * @tc.desc: try to SetParam with KEY_FRAME_RATE after start (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_FrameRate_AfterStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);
    param = ParcelableParam::Create();
    param->Set(KEY_FRAME_RATE, static_cast<uint32_t>(60));
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_HighPerfFlag_BeforeStart_001
 * @tc.desc: try to SetParam with boolean KEY_HIGH_PERF_FLAG (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_HighPerfFlag_BeforeStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param = ParcelableParam::Create();
    param->Set(KEY_HIGH_PERF_FLAG, true);
    ret = instance->SetParam(param);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_SetParam_HighPerfFlag_AfterStart_001
 * @tc.desc: try to SetParam with boolean KEY_HIGH_PERF_FLAG after start (start前后均支持)
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_SetParam_HighPerfFlag_AfterStart_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H264, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);

    sptr<ParcelableParam> param1 = ParcelableParam::Create();
    Resolution reso {1280, 720};
    param1->Set(KEY_RESOLUTION, reso);
    ret = instance->SetParam(param1);
    ASSERT_TRUE(ret == 0);

    ret = instance->Start();
    ASSERT_TRUE(ret == 0);

    sptr<ParcelableParam> param2 = ParcelableParam::Create();
    param2->Set(KEY_HIGH_PERF_FLAG, true);
    ret = instance->SetParam(param2);
    ASSERT_TRUE(ret != 0);
}

HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_GetParam_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    sptr<ParcelableParam> paramOut = ParcelableParam::Create();
    vector<string> keys {KEY_RESOLUTION};
    ret = instance->GetParam(keys, paramOut);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiTest_GetParam_002
 * @tc.desc: try to GetParam zcodec instance with SetParam
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_GetParam_002, TestSize.Level1)
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
 * @tc.name: ZCodecHdiTest_BindBufferByAlloc_001
 * @tc.desc: try to BindBufferByAlloc zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_BindBufferByAlloc_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    HdiBufferAllocInfo info {
        true, 0, width, height, GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);
}

/**
 * @tc.name: ZCodecHdiTest_BindBufferByAlloc_002
 * @tc.desc: try to BindBufferByAlloc zcodec instance after start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_BindBufferByAlloc_002, TestSize.Level1)
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
    HdiBufferAllocInfo info {
        true, 0, width, height, GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);
}

/**
 * @tc.name: ZCodecHdiTest_UnbindBuffers_001
 * @tc.desc: try to UnbindBuffers zcodec instance without start and bind
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_UnbindBuffers_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    const vector<uint64_t> ids {0};
    ret = instance->UnbindBuffers(ids);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiTest_UnbindBuffers_002
 * @tc.desc: try to UnbindBuffers zcodec instance after start without bind
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_UnbindBuffers_002, TestSize.Level1)
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
    const vector<uint64_t> ids {0};
    ret = instance->UnbindBuffers(ids);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: ZCodecHdiTest_UnbindBuffers_003
 * @tc.desc: try to UnbindBuffers zcodec instance after start with bind
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_UnbindBuffers_003, TestSize.Level1)
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

    HdiBufferAllocInfo info {
        true, 0, width, height, GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);

    const vector<uint64_t> ids {buf.id};
    ret = instance->UnbindBuffers(ids);
    ASSERT_TRUE(ret != 0); // 暂不支持unbind
}

/**
 * @tc.name: ZCodecHdiTest_QueueInputBuffers_001
 * @tc.desc: try to QueueInputBuffers zcodec instance without start
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_QueueInputBuffers_001, TestSize.Level1)
{
    int32_t ret = CreateZCodecByType(CodecType::H265, instance);
    ASSERT_TRUE(instance != nullptr && ret == 0);
    vector<HdiZBufferInfo> infos;
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ZCodecHdiTest_QueueInputBuffers_002
 * @tc.desc: try to QueueInputBuffers zcodec instance after start without BindBufferByAlloc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_QueueInputBuffers_002, TestSize.Level1)
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
    vector<HdiZBufferInfo> infos;
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_NE(ret, 0);}

/**
 * @tc.name: ZCodecHdiTest_QueueInputBuffers_003
 * @tc.desc: try to QueueInputBuffers zcodec instance after start with BindBufferByAlloc
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_QueueInputBuffers_003, TestSize.Level1)
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
    HdiBufferAllocInfo info {
        true, 0, width, height, GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    ret = instance->BindBufferByAlloc(info, nullptr, buf);
    ASSERT_TRUE(ret == 0 && buf.buf != nullptr);

    vector<HdiZBufferInfo> infos;
    infos.push_back(HdiZBufferInfo {.id = buf.id });
    vector<int32_t> errCodes;
    ret = instance->QueueInputBuffers(infos, errCodes);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: ZCodecHdiTest_BindBufferByUse_001
 * @tc.desc: try to BindBufferByUse zcodec instance - encoder should not support
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncTest, ZCodecHdiTest_BindBufferByUse_001, TestSize.Level1)
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

    sptr<ParcelableBuffer> buf = nullptr;
    uint64_t id;
    ret = instance->BindBufferByUse(buf, nullptr, id);
    ASSERT_TRUE(ret != 0);  // 编码器不支持主动bind buffer
}

INSTANTIATE_TEST_SUITE_P(
    ZCodecHdiEncFuncTest,
    ZCodecHdiEncTest,
    testing::Values(false, true));

}  // namespace
