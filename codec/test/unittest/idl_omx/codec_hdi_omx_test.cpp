/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Video.h>
#include <OMX_VideoExt.h>
#include <gtest/gtest.h>
#include <hdf_log.h>
#include <idisplay_gralloc.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <vector>
#include "codec_omx_ext.h"
#include "v1_0/codec_callback_service.h"
#include "v1_0/icodec_component.h"
#include "v1_0/icodec_component_manager.h"
#define HDF_LOG_TAG codec_hdi_test
using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using OHOS::HDI::Codec::V1_0::CodecCallbackService;
using OHOS::HDI::Codec::V1_0::CodecCompCapability;
using OHOS::HDI::Codec::V1_0::CompVerInfo;
using OHOS::HDI::Codec::V1_0::ICodecCallback;
using OHOS::HDI::Codec::V1_0::ICodecComponent;
using OHOS::HDI::Codec::V1_0::ICodecComponentManager;
using OHOS::HDI::Codec::V1_0::OmxCodecBuffer;
namespace {
    constexpr uint32_t WIDTH = 640;
    constexpr uint32_t HEIGHT = 480;
    constexpr int32_t INT_TO_STR_LEN = 32;
}
static OHOS::HDI::Display::V1_0::IDisplayGralloc *g_gralloc = nullptr;
static sptr<ICodecComponent> g_component = nullptr;
static sptr<ICodecComponent> g_componentHevc = nullptr;
static sptr<ICodecCallback> g_callback = nullptr;
static sptr<ICodecCallback> g_callbackHevc = nullptr;
static int32_t g_count = 0;
#ifdef SUPPORT_OMX
static std::string g_omxEncoderAvc("");
static std::string g_omxDecoderHevc("");
static uint32_t g_componentId = 0;
static uint32_t g_componentIdHevc = 0;
static OHOS::HDI::Codec::V1_0::OMX_VERSIONTYPE g_version;
namespace {
constexpr int FD_DEFAULT = -1;
constexpr int64_t APP_DATA = 3;
constexpr int32_t FRAMERATE = 30 << 16;
constexpr int32_t BUFFER_SIZE = 640 * 480 * 3;
constexpr uint32_t BUFFER_ID_ERROR = 65000;
}  // namespace
#endif  // SUPPORT_OMX
enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };
struct BufferInfo {
    std::shared_ptr<OmxCodecBuffer> omxBuffer;
    std::shared_ptr<OHOS::Ashmem> sharedMem;
    BufferHandle *bufferHandle;
    BufferInfo()
    {
        omxBuffer = nullptr;
        sharedMem = nullptr;
        bufferHandle = nullptr;
    }
    ~BufferInfo()
    {
        omxBuffer = nullptr;
        if (sharedMem != nullptr) {
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
        }
        if (bufferHandle != nullptr && g_gralloc != nullptr) {
            g_gralloc->FreeMem(*bufferHandle);
            bufferHandle = nullptr;
        }
    }
};
std::map<int32_t, std::shared_ptr<BufferInfo>> inputBuffers;
std::map<int32_t, std::shared_ptr<BufferInfo>> outputBuffers;
#ifdef SUPPORT_OMX
static void InitCodecBufferWithAshMem(enum PortIndex portIndex, int bufferSize, shared_ptr<OmxCodecBuffer> omxBuffer,
                                      shared_ptr<OHOS::Ashmem> sharedMem)
{
    omxBuffer->size = sizeof(OmxCodecBuffer);
    omxBuffer->version = g_version;
    omxBuffer->bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
    omxBuffer->fd = sharedMem->GetAshmemFd();
    omxBuffer->bufferhandle = nullptr;
    omxBuffer->allocLen = bufferSize;
    omxBuffer->fenceFd = FD_DEFAULT;
    omxBuffer->pts = 0;
    omxBuffer->flag = 0;
    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        omxBuffer->type = OHOS::HDI::Codec::V1_0::READ_ONLY_TYPE;
        sharedMem->MapReadAndWriteAshmem();
    } else {
        omxBuffer->type = OHOS::HDI::Codec::V1_0::READ_WRITE_TYPE;
        sharedMem->MapReadOnlyAshmem();
    }
}

static bool UseBufferOnPort(enum PortIndex portIndex, int bufferCount, int bufferSize)
{
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        if (omxBuffer == nullptr) {
            HDF_LOGE("%{public}s omxBuffer is null", __func__);
            return false;
        }

        int fd = OHOS::AshmemCreate(0, bufferSize);
        shared_ptr<OHOS::Ashmem> sharedMem = make_shared<OHOS::Ashmem>(fd, bufferSize);
        if (sharedMem == nullptr) {
            HDF_LOGE("%{public}s sharedMem is null", __func__);
            if (fd >= 0) {
                close(fd);
                fd = FD_DEFAULT;
            }
            return false;
        }
        InitCodecBufferWithAshMem(portIndex, bufferSize, omxBuffer, sharedMem);

        OmxCodecBuffer outBuffer;
        auto err = g_component->UseBuffer((uint32_t)portIndex, *omxBuffer, outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
            omxBuffer = nullptr;
            return false;
        }
        omxBuffer->bufferId = outBuffer.bufferId;
        omxBuffer->fd = FD_DEFAULT;
        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->sharedMem = sharedMem;
        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            inputBuffers.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        } else {
            outputBuffers.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        }
    }
    return true;
}
#endif  // SUPPORT_OMX
namespace {
class CodecHdiOmxTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp()
    {
        mgr_ = ICodecComponentManager::Get();
        g_gralloc = OHOS::HDI::Display::V1_0::IDisplayGralloc::Get();
        width_ = WIDTH;
        height_ = HEIGHT;
    }
    void TearDown()
    {}

public:
    sptr<ICodecComponentManager> mgr_ = nullptr;
    uint32_t width_;
    uint32_t height_;
};

template <typename T>
void InitParam(T &param)
{
    memset_s(&param, sizeof(param), 0x0, sizeof(param));
    param.nSize = sizeof(param);
    param.nVersion.nVersion = 1;
}

template <typename T>
void ObjectToVector(T &param, std::vector<int8_t> &vec)
{
    int8_t *paramPointer = (int8_t *)&param;
    vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
}

template <typename T>
void VectorToObject(std::vector<int8_t> &vec, T &param)
{
    (void)memcpy_s(&param, sizeof(param), vec.data(), vec.size());
}

static std::string &GetArrayStr(const std::vector<int32_t> &vec, std::string &arrayStr)
{
    arrayStr = ("[");
    int ret = 0;
    for (size_t i = 0; i < vec.size(); i++) {
        char value[INT_TO_STR_LEN] = {0};
        ret = sprintf_s(value, sizeof(value) - 1, "0x0%X, ", vec[i]);
        if (ret < 0) {
            HDF_LOGE("%{public}s: sprintf_s value failed, error code: %{public}d", __func__, ret);
            break;
        }
        arrayStr += value;
    }
    arrayStr += "]";
    return arrayStr;
}

static void PrintCapability(const CodecCompCapability &cap, int32_t index)
{
    std::string arrayStr("");
    HDF_LOGI("---------------------- component capability %{public}d ---------------------", index + 1);
    HDF_LOGI("role:%{public}d", cap.role);
    HDF_LOGI("type:%{public}d", cap.type);
    HDF_LOGI("compName:%{public}s", cap.compName.c_str());
    HDF_LOGI("supportProfiles:%{public}s", GetArrayStr(cap.supportProfiles, arrayStr).c_str());
    HDF_LOGI("maxInst:%{public}d", cap.maxInst);
    HDF_LOGI("isSoftwareCodec:%{public}d", cap.isSoftwareCodec);
    HDF_LOGI("processModeMask:0x0%{public}x", cap.processModeMask);
    HDF_LOGI("capsMask:0x0%{public}x", cap.capsMask);
    HDF_LOGI("bitRate.min:%{public}d", cap.bitRate.min);
    HDF_LOGI("bitRate.max:%{public}d", cap.bitRate.max);
    if (cap.compName.find("video") != std::string::npos) {
        HDF_LOGI("minSize.width:%{public}d", cap.port.video.minSize.width);
        HDF_LOGI("minSize.height:%{public}d", cap.port.video.minSize.height);
        HDF_LOGI("maxSize.width:%{public}d", cap.port.video.maxSize.width);
        HDF_LOGI("maxSize.height:%{public}d", cap.port.video.maxSize.height);
        HDF_LOGI("widthAlignment:%{public}d", cap.port.video.whAlignment.widthAlignment);
        HDF_LOGI("heightAlignment:%{public}d", cap.port.video.whAlignment.heightAlignment);
        HDF_LOGI("blockCount.min:%{public}d", cap.port.video.blockCount.min);
        HDF_LOGI("blockCount.max:%{public}d", cap.port.video.blockCount.max);
        HDF_LOGI("blocksPerSecond.min:%{public}d", cap.port.video.blocksPerSecond.min);
        HDF_LOGI("blocksPerSecond.max:%{public}d", cap.port.video.blocksPerSecond.max);
        HDF_LOGI("blockSize.width:%{public}d", cap.port.video.blockSize.width);
        HDF_LOGI("blockSize.height:%{public}d", cap.port.video.blockSize.height);
        HDF_LOGI("supportPixFmts:%{public}s", GetArrayStr(cap.port.video.supportPixFmts, arrayStr).c_str());
    } else {
        HDF_LOGI(":%{public}s", GetArrayStr(cap.port.audio.sampleFormats, arrayStr).c_str());
        HDF_LOGI(":%{public}s", GetArrayStr(cap.port.audio.sampleRate, arrayStr).c_str());
        HDF_LOGI(":%{public}s", GetArrayStr(cap.port.audio.channelLayouts, arrayStr).c_str());
        HDF_LOGI(":%{public}s", GetArrayStr(cap.port.audio.channelCount, arrayStr).c_str());
    }
    HDF_LOGI("-------------------------------------------------------------------");
}

// Test Init
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiInitTest_001, TestSize.Level1)
{
    auto tempMgr = ICodecComponentManager::Get();
    ASSERT_TRUE(tempMgr != nullptr);
}

// Test GetComponentNum
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetComponentNumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(mgr_ != nullptr);
    auto err = mgr_->GetComponentNum(g_count);
    ASSERT_EQ(err, HDF_SUCCESS);
}

// Test GetComponentCapabilityList
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetCapabilityListTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_count > 0);
    std::vector<OHOS::HDI::Codec::V1_0::CodecCompCapability> caps;
    ASSERT_TRUE(mgr_ != nullptr);
    auto err = mgr_->GetComponentCapabilityList(caps, g_count);
    ASSERT_EQ(err, HDF_SUCCESS);
    for (size_t i = 0; i < caps.size(); i++) {
        PrintCapability(caps[i], i);
        if (caps[i].role == OHOS::HDI::Codec::V1_0::MEDIA_ROLETYPE_VIDEO_AVC &&
            caps[i].type == OHOS::HDI::Codec::V1_0::VIDEO_ENCODER) {
            g_omxEncoderAvc = caps[i].compName;
            std::cout << "avc comp name:" << g_omxEncoderAvc << std::endl;
        } else if (caps[i].role == OHOS::HDI::Codec::V1_0::MEDIA_ROLETYPE_VIDEO_HEVC &&
                   caps[i].type == OHOS::HDI::Codec::V1_0::VIDEO_DECODER) {
            g_omxDecoderHevc = caps[i].compName;
            std::cout << "hevc comp name:" << g_omxEncoderAvc << std::endl;
        }
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetCapabilityListTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_count > 0);
    ASSERT_TRUE(mgr_ != nullptr);
    std::vector<OHOS::HDI::Codec::V1_0::CodecCompCapability> caps;
    auto err = mgr_->GetComponentCapabilityList(caps, 1);
    ASSERT_EQ(err, HDF_SUCCESS);
    for (size_t i = 0; i < caps.size(); i++) {
        PrintCapability(caps[i], i);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetCapabilityListTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_count > 0);
    ASSERT_TRUE(mgr_ != nullptr);
    std::vector<OHOS::HDI::Codec::V1_0::CodecCompCapability> caps;
    auto err = mgr_->GetComponentCapabilityList(caps, g_count + 1);
    ASSERT_EQ(err, HDF_SUCCESS);
    for (size_t i = 0; i < caps.size(); i++) {
        PrintCapability(caps[i], i);
    }
}

#ifdef SUPPORT_OMX
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiCreateComponentTest_001, TestSize.Level1)
{
    ASSERT_TRUE(mgr_ != nullptr);
    sptr<ICodecCallback> callback = new CodecCallbackService();
    sptr<ICodecComponent> component = nullptr;
    uint32_t componentId = 0;
    int32_t ret = mgr_->CreateComponent(component, componentId, (char *)"compName", APP_DATA, callback);
    ASSERT_NE(ret, HDF_SUCCESS);
    ASSERT_TRUE(component == nullptr);
    ASSERT_TRUE(componentId == 0);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiCreateComponentTest_002, TestSize.Level1)
{
    std::cout << "avc comp name:" << g_omxEncoderAvc << std::endl;
    ASSERT_TRUE(mgr_ != nullptr);
    ASSERT_TRUE(!g_omxEncoderAvc.empty());
    g_callback = new CodecCallbackService();
    auto err = mgr_->CreateComponent(g_component, g_componentId, g_omxEncoderAvc.c_str(), APP_DATA, g_callback);
    ASSERT_EQ(err, HDF_SUCCESS);
    ASSERT_TRUE(g_componentId != 0);
    ASSERT_TRUE(g_component != nullptr);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiCreateComponentTest_003, TestSize.Level1)
{
    ASSERT_TRUE(mgr_ != nullptr);
    ASSERT_TRUE(!g_omxDecoderHevc.empty());
    g_callbackHevc = new CodecCallbackService();
    auto err =
        mgr_->CreateComponent(g_componentHevc, g_componentIdHevc, g_omxDecoderHevc.c_str(), APP_DATA, g_callbackHevc);
    ASSERT_EQ(err, HDF_SUCCESS);
    ASSERT_TRUE(g_componentIdHevc != 0);
    ASSERT_TRUE(g_componentHevc != nullptr);
}

// Test GetComponentVersion
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiComponentVersionTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_componentHevc != nullptr);
    ASSERT_TRUE(mgr_ != nullptr);
    CompVerInfo verInfo;
    int32_t ret = g_componentHevc->GetComponentVersion(verInfo);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetComponentVersionTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    ASSERT_TRUE(mgr_ != nullptr);
    CompVerInfo verInfo;
    int32_t ret = g_component->GetComponentVersion(verInfo);
    ASSERT_EQ(ret, HDF_SUCCESS);
    g_version.nVersion = verInfo.compVersion.nVersion;
}

// Test GetParameter
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
    VectorToObject(outParam, param);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexVideoStartUnused, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PORT_PARAM_TYPE param;
    InitParam(param);

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = g_component->GetParameter(OMX_IndexParamVideoInit, inParam, outParam);
    VectorToObject(outParam, param);
    std::cout << "nStartPortNumber:" << param.nStartPortNumber << ", nPorts:" << param.nPorts << std::endl;
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Test SetParameter
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    int32_t ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    int32_t ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> paramVec;
    int32_t ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    int32_t ret = g_component->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    std::vector<int8_t> paramVec;

    ObjectToVector(param, paramVec);
    int32_t ret = g_component->SetParameter(OMX_IndexVideoStartUnused, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test GetConfig
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    int32_t ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);

    VectorToObject(outParam, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    int32_t ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);

    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    std::vector<int8_t> outParam;
    int32_t ret = g_component->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);

    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    int32_t ret = g_component->GetConfig(OMX_IndexVideoStartUnused, inParam, outParam);

    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test SetConfig
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    param.nEncodeBitrate = FRAMERATE;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    int32_t ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.nEncodeBitrate = FRAMERATE;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    int32_t ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> inParam;
    int32_t ret = g_component->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.nEncodeBitrate = FRAMERATE;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    int32_t ret = g_component->SetConfig(OMX_IndexVideoStartUnused, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test GetExtensionIndex
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetExtensionIndexTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t indexType = 0;
    int32_t ret = g_component->GetExtensionIndex("OMX.Topaz.index.param.extended_video", indexType);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetExtensionIndexTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t indexType = 0;
    int32_t ret = g_component->GetExtensionIndex("OMX.Topaz.index.param.test", indexType);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test GetState
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t state = OMX_StateInvalid;
    int32_t ret = g_component->GetState(state);
    ASSERT_EQ(state, OMX_StateLoaded);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Test ComponentTunnelRequest
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiTunnelRequestTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    const int32_t tunneledComp = 1002;
    const uint32_t tunneledPort = 101;
    OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE tunnelSetup;
    tunnelSetup.eSupplier = OHOS::HDI::Codec::V1_0::OMX_BufferSupplyInput;

    int32_t ret = g_component->ComponentTunnelRequest((uint32_t)PortIndex::PORT_INDEX_OUTPUT, tunneledComp,
                                                      tunneledPort, tunnelSetup, tunnelSetup);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test State Change
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiLoadedToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    int32_t ret = g_component->SendCommand(OMX_CommandStateSet, OMX_StateIdle, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

struct OmxCodecBuffer allocBuffer;
// Test AllocateBuffer
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_INVALID;
    allocBuffer.size = sizeof(allocBuffer);  // has no effect
    allocBuffer.fenceFd = FD_DEFAULT;
    allocBuffer.version = g_version;
    allocBuffer.allocLen = BUFFER_SIZE;
    allocBuffer.pts = 0;
    allocBuffer.fd = FD_DEFAULT;
    allocBuffer.flag = 0;
    allocBuffer.bufferhandle = nullptr;
    allocBuffer.type = OHOS::HDI::Codec::V1_0::READ_ONLY_TYPE;

    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_VIRTUAL_ADDR;

    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_INVALID;

    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_VIRTUAL_ADDR;

    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test UseBuffer
OmxCodecBuffer omxBuffer;
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferhandle = nullptr;
    omxBuffer.fd = FD_DEFAULT;
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_INVALID;
    omxBuffer.version = g_version;
    omxBuffer.allocLen = 0;
    omxBuffer.fenceFd = FD_DEFAULT;
    omxBuffer.pts = 0;
    omxBuffer.flag = 0;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_VIRTUAL_ADDR;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_INVALID;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_VIRTUAL_ADDR;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    omxBuffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;

    OmxCodecBuffer outBuffer;
    auto err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, omxBuffer, outBuffer);
    ASSERT_NE(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_007, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_INPUT;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto err = g_component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);

    ASSERT_EQ(err, HDF_SUCCESS);
    VectorToObject(outParam, param);
    int bufferSize = param.nBufferSize;
    int bufferCount = param.nBufferCountActual;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, bufferCount - 1, bufferSize);
    ASSERT_TRUE(ret);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_008, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    AllocInfo alloc = {.width = this->width_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};
    ASSERT_TRUE(g_gralloc != nullptr);
    BufferHandle *bufferHandle = nullptr;
    auto err = g_gralloc->AllocMem(alloc, bufferHandle);
    ASSERT_EQ(err, DISPLAY_SUCCESS);
    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    size_t handleSize =
        sizeof(BufferHandle) + (sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts));
    omxBuffer->size = sizeof(OmxCodecBuffer);
    omxBuffer->version = g_version;
    omxBuffer->bufferType = CODEC_BUFFER_TYPE_HANDLE;
    omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    omxBuffer->allocLen = handleSize;
    omxBuffer->fenceFd = FD_DEFAULT;
    omxBuffer->fd = FD_DEFAULT;
    omxBuffer->pts = 0;
    omxBuffer->flag = 0;

    OmxCodecBuffer outBuffer;
    err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, *omxBuffer.get(), outBuffer);
    omxBuffer->bufferhandle = nullptr;

    ASSERT_EQ(err, HDF_SUCCESS);
    omxBuffer->bufferId = outBuffer.bufferId;

    std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
    ASSERT_TRUE(bufferInfo != nullptr);
    bufferInfo->omxBuffer = omxBuffer;
    bufferInfo->bufferHandle = bufferHandle;
    inputBuffers.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_009, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_OUTPUT;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto err = g_component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
    ASSERT_EQ(err, HDF_SUCCESS);
    VectorToObject(outParam, param);

    int bufferSize = param.nBufferSize;
    int bufferCount = param.nBufferCountActual;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, bufferCount - 1, bufferSize);
    ASSERT_TRUE(ret);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_010, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    AllocInfo alloc = {.width = this->width_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};
    ASSERT_TRUE(g_gralloc != nullptr);
    BufferHandle *bufferHandle = nullptr;
    auto err = g_gralloc->AllocMem(alloc, bufferHandle);
    ASSERT_EQ(err, DISPLAY_SUCCESS);
    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    size_t handleSize =
        sizeof(BufferHandle) + (sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts));
    omxBuffer->size = sizeof(OmxCodecBuffer);
    omxBuffer->version = g_version;
    omxBuffer->bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
    omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    omxBuffer->allocLen = handleSize;
    omxBuffer->fenceFd = FD_DEFAULT;
    omxBuffer->fd = FD_DEFAULT;
    omxBuffer->pts = 0;
    omxBuffer->flag = 0;

    OmxCodecBuffer outBuffer;
    err = g_component->UseBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, *omxBuffer.get(), outBuffer);
    omxBuffer->bufferhandle = nullptr;

    ASSERT_EQ(err, HDF_SUCCESS);
    omxBuffer->bufferId = outBuffer.bufferId;

    std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
    ASSERT_TRUE(bufferInfo != nullptr);
    bufferInfo->omxBuffer = omxBuffer;
    bufferInfo->bufferHandle = bufferHandle;
    outputBuffers.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_011, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_INPUT;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto err = g_component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
    ASSERT_EQ(err, HDF_SUCCESS);
    VectorToObject(outParam, param);

    int bufferSize = param.nBufferSize;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, 1, bufferSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_012, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_OUTPUT;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto err = g_component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
    ASSERT_EQ(err, HDF_SUCCESS);
    VectorToObject(outParam, param);

    int bufferSize = param.nBufferSize;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, 1, bufferSize);
    ASSERT_FALSE(ret);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_005, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;

    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    allocBuffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
    OmxCodecBuffer outBuffer;
    int32_t ret = g_component->AllocateBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseEglImageTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct OmxCodecBuffer buffer, outbuffer;
    buffer.fenceFd = FD_DEFAULT;
    buffer.version = g_version;
    buffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
    buffer.allocLen = BUFFER_SIZE;
    buffer.fd = FD_DEFAULT;
    buffer.bufferhandle = nullptr;
    buffer.pts = 0;
    buffer.flag = 0;
    buffer.type = OHOS::HDI::Codec::V1_0::READ_ONLY_TYPE;
    auto eglImage = std::make_unique<int8_t[]>(BUFFER_SIZE);
    ASSERT_TRUE(eglImage != nullptr);
    std::vector<int8_t> eglImageVec;
    eglImageVec.assign(eglImage.get(), eglImage.get() + BUFFER_SIZE);

    int32_t ret = g_component->UseEglImage((uint32_t)PortIndex::PORT_INDEX_INPUT, buffer, outbuffer, eglImageVec);
    ASSERT_NE(ret, HDF_SUCCESS);
    eglImage = nullptr;
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiWaitStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    // wait for Idle status
    uint32_t state = OMX_StateInvalid;
    do {
        usleep(100);
        auto ret = g_component->GetState(state);
        ASSERT_EQ(ret, HDF_SUCCESS);
    } while (state != OMX_StateIdle);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFillThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    int32_t ret = g_component->SendCommand(OMX_CommandStateSet, OMX_StateExecuting, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    uint32_t state = OMX_StateInvalid;
    do {
        ret = g_component->GetState(state);
        ASSERT_EQ(ret, HDF_SUCCESS);
        usleep(100);
    } while (state != OMX_StateExecuting);

    // fill this buffer need OMX_StateExecuting
    auto iter = outputBuffers.begin();
    if (iter != outputBuffers.end()) {
        int32_t ret = g_component->FillThisBuffer(*iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFillThisBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = outputBuffers.begin();
    if (iter != outputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        auto tempId = omxBuffer->bufferId;
        omxBuffer->bufferId = BUFFER_ID_ERROR;
        int32_t ret = g_component->FillThisBuffer(*omxBuffer.get());
        ASSERT_NE(ret, HDF_SUCCESS);
        omxBuffer->bufferId = tempId;
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    if (iter != inputBuffers.end()) {
        int32_t ret = g_component->EmptyThisBuffer(*iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyThisBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    if (iter != inputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        auto tempId = omxBuffer->bufferId;
        omxBuffer->bufferId = BUFFER_ID_ERROR;
        int32_t ret = g_component->EmptyThisBuffer(*iter->second->omxBuffer.get());
        ASSERT_NE(ret, HDF_SUCCESS);
        omxBuffer->bufferId = tempId;
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetCallbackTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    if (g_callback != nullptr) {
        g_callback = nullptr;
    }
    g_callback = new CodecCallbackService();
    ASSERT_TRUE(g_callback != nullptr);
    int32_t ret = g_component->SetCallbacks(g_callback, APP_DATA);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetCallbackTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->SetCallbacks(nullptr, APP_DATA);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiRoleEnumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<uint8_t> role;
    int32_t ret = g_component->ComponentRoleEnum(role, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiExecutingToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    int32_t ret = g_component->SendCommand(OMX_CommandStateSet, OMX_StateIdle, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = outputBuffers.begin();
    if (iter != outputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        auto tempId = omxBuffer->bufferId;
        omxBuffer->bufferId = BUFFER_ID_ERROR;
        int32_t ret = g_component->FreeBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, *omxBuffer);
        ASSERT_NE(ret, HDF_SUCCESS);
        omxBuffer->bufferId = tempId;
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = outputBuffers.begin();
    while (iter != outputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        int32_t ret = g_component->FreeBuffer((uint32_t)PortIndex::PORT_INDEX_OUTPUT, *omxBuffer);
        ASSERT_EQ(ret, HDF_SUCCESS);
        iter = outputBuffers.erase(iter);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    if (iter != inputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        auto tempId = omxBuffer->bufferId;
        omxBuffer->bufferId = BUFFER_ID_ERROR;
        int32_t ret = g_component->FreeBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, *omxBuffer);
        ASSERT_NE(ret, HDF_SUCCESS);
        omxBuffer->bufferId = tempId;
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    while (iter != inputBuffers.end()) {
        auto omxBuffer = iter->second->omxBuffer;
        int32_t ret = g_component->FreeBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, *omxBuffer);
        ASSERT_EQ(ret, HDF_SUCCESS);
        iter = inputBuffers.erase(iter);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiIdleToLoadedTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    int32_t ret = g_component->SendCommand(OMX_CommandStateSet, OMX_StateLoaded, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiWaitIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint32_t state = OMX_StateInvalid;
    do {
        usleep(100);
        auto ret = g_component->GetState(state);
        ASSERT_EQ(ret, HDF_SUCCESS);
    } while (state != OMX_StateLoaded);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiDeInitTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->ComponentDeInit();
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiDestoryComponentTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    ASSERT_TRUE(mgr_ != nullptr);
    int ret = mgr_->DestroyComponent(g_componentId);
    ASSERT_EQ(ret, HDF_SUCCESS);
    g_component = nullptr;

    ASSERT_TRUE(g_componentHevc != nullptr);
    ASSERT_TRUE(mgr_ != nullptr);
    ret = mgr_->DestroyComponent(g_componentIdHevc);
    ASSERT_EQ(ret, HDF_SUCCESS);
    g_componentHevc = nullptr;
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiReleaseTest_001, TestSize.Level1)
{
    ASSERT_TRUE(mgr_ != nullptr);
    ASSERT_TRUE(g_callback != nullptr);
    ASSERT_TRUE(g_callbackHevc != nullptr);
    g_callback = nullptr;
    g_callbackHevc = nullptr;
    mgr_ = nullptr;
}
#endif  // SUPPORT_OMX
}  // namespace
