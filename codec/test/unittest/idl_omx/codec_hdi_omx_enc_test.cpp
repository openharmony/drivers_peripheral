/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <vector>
#include "codec_function_utils.h"
#include "v3_0/codec_callback_service.h"
#include "v3_0/codec_ext_types.h"

#define ERR_COUNT (-1)

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
using OHOS::HDI::Codec::V3_0::CodecType;
using OHOS::HDI::Codec::V3_0::AvCodecRole;
using OHOS::HDI::Codec::V3_0::MEDIA_ROLETYPE_VIDEO_AVC;
using OHOS::HDI::Codec::V3_0::ICodecComponent;
using OHOS::HDI::Codec::V3_0::ICodecCallback;
using OHOS::HDI::Codec::V3_0::ICodecComponentManager;
using OHOS::HDI::Codec::V3_0::FunctionUtil;
using OHOS::HDI::Codec::V3_0::PortIndex;
using OHOS::HDI::Codec::V3_0::CodecCompCapability;
using OHOS::HDI::Codec::V3_0::CodecCallbackService;
using OHOS::HDI::Codec::V3_0::CodecCommandType;
using OHOS::HDI::Codec::V3_0::CodecStateType;
using OHOS::HDI::Codec::V3_0::OmxCodecBuffer;
using OHOS::HDI::Codec::V3_0::CompVerInfo;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_INVALID;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_LOADED;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_IDLE;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_EXECUTING;
using OHOS::HDI::Codec::V3_0::CODEC_COMMAND_STATE_SET;

namespace {
constexpr CodecType TYPE = CodecType::VIDEO_ENCODER;
constexpr AvCodecRole ROLE = MEDIA_ROLETYPE_VIDEO_AVC;
static sptr<ICodecComponent> g_component = nullptr;
static sptr<ICodecCallback> g_callback = nullptr;
static sptr<ICodecComponentManager> g_manager = nullptr;
static OHOS::HDI::Codec::V3_0::CodecVersionType g_version;
static std::string g_compName = "";

class CodecHdiOmxEncTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_manager = ICodecComponentManager::Get();
        int32_t count = 0;
        auto ret = g_manager->GetComponentNum(count);
        ASSERT_EQ(ret, HDF_SUCCESS);
        if (count <= 0) {
            return;
        }

        std::vector<CodecCompCapability> capList;
        auto err = g_manager->GetComponentCapabilityList(capList, count);
        ASSERT_TRUE(err == HDF_SUCCESS);
        for (auto cap : capList) {
            if (cap.type == TYPE && cap.role == ROLE) {
                g_compName = cap.compName;
                break;
            }
        }
    }

    static void TearDownTestCase()
    {
        g_manager = nullptr;
    }

    void SetUp()
    {
        ASSERT_TRUE(g_manager != nullptr && !g_compName.empty());
        g_callback = new CodecCallbackService();
        ASSERT_TRUE(g_callback != nullptr);
        auto ret = g_manager->CreateComponent(g_component, componentId_, g_compName.data(), APP_DATA, g_callback);
        ASSERT_EQ(ret, HDF_SUCCESS);
        ret = g_manager->CreateComponent(g_component, componentId_, "", APP_DATA, g_callback);
        ASSERT_TRUE(ret != HDF_SUCCESS);
        struct CompVerInfo verInfo;
        ret = g_component->GetComponentVersion(verInfo);
        ASSERT_EQ(ret, HDF_SUCCESS);
        g_version = verInfo.compVersion;

        func_ = new FunctionUtil(g_version);
        ASSERT_TRUE(func_ != nullptr);
    }

    void TearDown()
    {
        std::vector<int8_t> cmdData;
        if (g_component != nullptr) {
            g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
        }
        if (g_manager != nullptr && g_component != nullptr) {
            g_manager->DestroyComponent(componentId_);
        }
        g_component = nullptr;
        g_callback = nullptr;
        func_ = nullptr;
    }

public:
    uint32_t componentId_ = 0;
    sptr<FunctionUtil> func_ = nullptr;
    const static uint32_t inputIndex = static_cast<uint32_t>(PortIndex::INDEX_INPUT);
    const static uint32_t outputIndex = static_cast<uint32_t>(PortIndex::INDEX_OUTPUT);
};

// Test GetComponentVersion
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetVersionTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct CompVerInfo verInfo;
    auto ret = g_component->GetComponentVersion(verInfo);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    CodecVideoPortFormatParam pixFormat;
    func_->InitExtParam(pixFormat);
    pixFormat.portIndex = outputIndex;
    pixFormat.codecColorIndex = 0;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    CodecVideoPortFormatParam pixFormat;
    func_->InitExtParam(pixFormat);
    pixFormat.portIndex = inputIndex;
    pixFormat.codecColorIndex = 0;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Test GetParameter
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    std::vector <int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    int32_t ret = memset_s(&param, sizeof(param), 0, sizeof(param));
    ASSERT_EQ(ret, EOK);
    param.nPortIndex = inputIndex;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetParameterTest_007, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexVideoStartUnused, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(param, paramVec);
    auto ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    int32_t ret = memset_s(&param, sizeof(param), 0, sizeof(param));
    ASSERT_EQ(ret, EOK);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(param, paramVec);
    ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> paramVec;
    auto ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(param, paramVec);
    auto ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(param, paramVec);
    auto ret = g_component->SetParameter(OMX_IndexVideoStartUnused, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    CodecVideoPortFormatParam pixFormat;
    func_->InitExtParam(pixFormat);
    pixFormat.portIndex = inputIndex;
    pixFormat.codecColorIndex = 0;
    std::vector<int8_t> inParam;
    func_->ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);

    pixFormat.codecColorFormat = PIXEL_FMT_YCBCR_420_SP;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(pixFormat, paramVec);
    ret = g_component->SetParameter(OMX_IndexCodecVideoPortFormat, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

#ifndef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterTest_007, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_CONFIG_BOOLEANTYPE param {};
    func_->InitParam(param);
    param.bEnabled = OMX_TRUE;
    std::vector<int8_t> paramVec;
    func_->ObjectToVector(param, paramVec);
    auto ret = g_component->SetParameter(OMX_IndexParamLowLatency, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif
//Test DMA Buffer
#ifdef SUPPORT_DMA_BUFFER
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiDMABufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    SupportBufferType bufferType;
    func_->InitExtParam(bufferType);
    bufferType.portIndex = outputIndex;
    std::vector<int8_t> inParam, outParam;
    func_->ObjectToVector(bufferType, inParam);
    auto ret = g_component->GetParameter(OMX_IndexParamSupportBufferType, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
    func_->VectorToObject(outParam, bufferType);
    ASSERT_TRUE(bufferType.bufferTypes & CODEC_BUFFER_TYPE_DMA_MEM_FD) ;
}
#endif

// Test GetConfig
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    std::vector<int8_t> outParam;
    auto ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = g_component->GetConfig(OMX_IndexVideoStartUnused, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test SetConfig
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = outputIndex;
    param.nEncodeBitrate = FRAMERATE;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    auto ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = inputIndex;
    param.nEncodeBitrate = FRAMERATE;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    auto ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    auto ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    func_->InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    func_->ObjectToVector(param, inParam);
    auto ret = g_component->SetConfig(OMX_IndexVideoStartUnused, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Test GetExtensionIndex
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetExtensionIndexTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t indexType = 0;
    auto ret = g_component->GetExtensionIndex("OMX.Topaz.index.param.extended_video", indexType);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetExtensionIndexTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t indexType = 0;
    auto ret = g_component->GetExtensionIndex("OMX.Topaz.index.param.extended_test", indexType);
    ASSERT_NE(ret, HDF_SUCCESS);
}


// Test GetState
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiGetStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    CodecStateType state = CODEC_STATE_INVALID;
    int32_t ret = g_component->GetState(state);
    ASSERT_EQ(state, CODEC_STATE_LOADED);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Test ComponentTunnelRequest
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiTunnelRequestTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    const int32_t tunneledComp = 1002;
    const uint32_t tunneledPort = 101;
    OHOS::HDI::Codec::V3_0::CodecTunnelSetupType tunnelSetup;
    tunnelSetup.supplier = OHOS::HDI::Codec::V3_0::CODEC_BUFFER_SUPPLY_INPUT;

    auto ret = g_component->ComponentTunnelRequest(outputIndex, tunneledComp, tunneledPort,
        tunnelSetup, tunnelSetup);
    ASSERT_NE(ret, HDF_SUCCESS);
}
#endif

#ifdef SUPPORT_OMX_EXTEND
// Test SendCommand
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiLoadedToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferAndFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto err = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    struct OmxCodecBuffer outBuffer;
    err = g_component->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);

    err = g_component->FreeBuffer(inputIndex, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiAllocateBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto err = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    func_->InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    allocBuffer.type = READ_WRITE_TYPE;
    struct OmxCodecBuffer outBuffer;
    err = g_component->AllocateBuffer(outputIndex, allocBuffer, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);

    err = g_component->FreeBuffer(outputIndex, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);
}
#endif

// Test UseBuffer
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->UseBuffer(inputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->UseBuffer(outputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->UseBuffer(inputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = g_component->UseBuffer(outputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Use buffer on input index
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);

    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    func_->InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_HANDLE);
    auto err = func_->FillCodecBufferWithBufferHandle(omxBuffer);
    ASSERT_TRUE(err);

    OmxCodecBuffer outBuffer;
    ret = g_component->UseBuffer(inputIndex, *omxBuffer.get(), outBuffer);
    omxBuffer->bufferId = outBuffer.bufferId;
    ASSERT_EQ(ret, HDF_SUCCESS);
    ret = g_component->FreeBuffer(inputIndex, outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Use Buffer on output index
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);

    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    func_->InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);

    OmxCodecBuffer outBuffer;
    ret = g_component->UseBuffer(outputIndex, *omxBuffer.get(), outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ret = g_component->FreeBuffer(outputIndex, outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Use buffer on input index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);

    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);
    err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_INPUT, 1, param.nBufferSize);
    ASSERT_FALSE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
}

// Use buffer on output index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseBufferAndFreeBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);

    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);
    err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, 1, param.nBufferSize);
    ASSERT_FALSE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
}
#endif

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiEmptyAndFillBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);

    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_EXECUTING);
    ASSERT_TRUE(err);
    err = func_->FillAndEmptyAllBuffer(g_component, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);
    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);

    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
    err = func_->WaitState(g_component, CODEC_STATE_LOADED);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiEmptyAndFillBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    auto err = func_->InitBufferHandleParameter(g_component, param, inputIndex, CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);
    ASSERT_TRUE(err);
    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->UseDynaBuffer(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_EXECUTING);
    ASSERT_TRUE(err);
    err = func_->FillAndEmptyAllBuffer(g_component, CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);
    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);

    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
    err = func_->WaitState(g_component, CODEC_STATE_LOADED);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiEmptyAndFillBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    auto err = func_->AllocateBufferOnPort(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);

    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->AllocateBufferOnPort(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_EXECUTING);
    ASSERT_TRUE(err);
    err = func_->FillAndEmptyAllBuffer(g_component, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);
    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);

    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
    err = func_->WaitState(g_component, CODEC_STATE_LOADED);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiUseEglImageTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    auto eglImage = std::make_unique<int8_t[]>(BUFFER_SIZE);
    ASSERT_TRUE(eglImage != nullptr);
    std::vector<int8_t> eglImageVec;
    eglImageVec.assign(eglImage.get(), eglImage.get() + BUFFER_SIZE);
    struct OmxCodecBuffer outbuffer;
    int32_t ret = g_component->UseEglImage(inputIndex, omxBuffer, outbuffer, eglImageVec);
    ASSERT_NE(ret, HDF_SUCCESS);
    eglImage = nullptr;
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiFillThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = g_component->FillThisBuffer(omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiEmptyThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = g_component->EmptyThisBuffer(omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifndef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetParameterWithBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OHOS::HDI::Codec::V3_0::CodecParamOverlay param;
    func_->InitExtParam(param);
    param.size = sizeof(param);
    param.enable = true;
    param.dstX = 0;
    param.dstY = 0;
    param.dstW = static_cast<uint32_t>(WIDTH);
    param.dstH = static_cast<uint32_t>(HEIGHT);
    int8_t* p = reinterpret_cast<int8_t*>(&param);
    std::vector<int8_t> inVec(p, p + sizeof(param));
    auto omxBuffer = std::make_shared<struct OmxCodecBuffer>();
    func_->FillCodecBufferWithBufferHandle(omxBuffer);
    auto ret = g_component->SetParameterWithBuffer(OHOS::HDI::Codec::V3_0::Codec_IndexParamOverlayBuffer, inVec, *omxBuffer.get());
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetCallbackTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    g_callback = new CodecCallbackService();
    ASSERT_TRUE(g_callback != nullptr);
    auto ret = g_component->SetCallbacks(g_callback, APP_DATA);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiSetCallbackTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto ret = g_component->SetCallbacks(nullptr, APP_DATA);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiRoleEnumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<uint8_t> role;
    auto ret = g_component->ComponentRoleEnum(role, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiRoleEnumTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<uint8_t> role;
    auto ret = g_component->ComponentRoleEnum(role, MAX_ROLE_INDEX);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Release input buffer
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = g_component->FreeBuffer(outputIndex, omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Release input buffer
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer omxBuffer;
    func_->InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = g_component->FreeBuffer(inputIndex, omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// When ComponentDeInit, must change to Loaded State
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiDeInitTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto ret = g_component->ComponentDeInit();
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

#ifdef SUPPORT_HIGH_WORK_FREQUENCY
HWTEST_F(CodecHdiOmxEncTest, HdfCodecHdiHighWorkingFrequencyTest_001, TestSize.Level1)
{
    const std::string processName = "cast_engine_service";
    std::vector<int8_t> paramVec;

    ASSERT_TRUE(g_component != nullptr);

    ProcessNameParam nameParam;
    func_->InitExtParam(nameParam);
    int32_t ret = strcpy_s(nameParam.processName, sizeof(nameParam.processName), processName.c_str());
    ASSERT_TRUE(ret == EOK);
    func_->ObjectToVector(nameParam, paramVec);
    ret = g_component->SetParameter(OMX_IndexParamProcessName, paramVec);
    ASSERT_TRUE(ret == HDF_SUCCESS);

    WorkingFrequencyParam freqParam;
    std::vector<int8_t> inParam;
    std::vector<int8_t> outParam;

    func_->InitExtParam(freqParam);
    func_->ObjectToVector(freqParam, inParam);
    ret = g_component->GetParameter(OMX_IndexParamWorkingFrequency, inParam, outParam);
    ASSERT_TRUE(ret == HDF_SUCCESS);
    func_->VectorToObject(outParam, freqParam);

    // 设置为最高档
    freqParam.level = freqParam.level - 1;
    func_->ObjectToVector(freqParam, inParam);
    ret = g_component->SetParameter(OMX_IndexParamWorkingFrequency, inParam);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}
#endif
}  // namespace
