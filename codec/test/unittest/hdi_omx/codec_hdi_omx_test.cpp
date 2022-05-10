/*
 * Copyright (c) 2021 Shenzhen Kaihong DID Co., Ltd.
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
#include <ashmem.h>
#include <gtest/gtest.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include <servmgr_hdi.h>

#include "codec_callback_type_stub.h"
#include "codec_component_manager.h"
#include "codec_component_type.h"
#include "hdf_io_service_if.h"

#define HDF_LOG_TAG codec_hdi_test

using namespace std;
using namespace testing::ext;

namespace {
struct CodecComponentManager *g_manager = nullptr;
int32_t g_count = 0;

#ifdef RK
#define COMPONENT_NAME "OMX.rk.video_encoder.avc"
#endif

constexpr int32_t INT_TO_STR_LEN = 32;
constexpr int32_t ARRAY_TO_STR_LEN = 1000;

#ifdef COMPONENT_NAME
struct CodecComponentType *g_component = nullptr;
union OMX_VERSIONTYPE g_version;

constexpr int32_t BUFFER_SIZE = 640 * 480 * 3;
constexpr int32_t ROLE_LEN = 240;
constexpr int32_t FRAMERATE = 30 << 16;
enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };

template <typename T>
void InitParam(T &param)
{
    memset_s(&param, sizeof(param), 0x0, sizeof(param));
    param.nSize = sizeof(param);
    param.nVersion = g_version;
}

struct BufferInfo {
    std::shared_ptr<OmxCodecBuffer> omxBuffer;
    std::shared_ptr<OHOS::Ashmem> sharedMem;
    BufferInfo()
    {
        omxBuffer = nullptr;
        sharedMem = nullptr;
    }
    ~BufferInfo()
    {
        omxBuffer = nullptr;
        if (sharedMem) {
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
        }
    }
};
std::map<int32_t, std::shared_ptr<BufferInfo>> inputBuffers;
std::map<int32_t, std::shared_ptr<BufferInfo>> outputBuffers;

static bool UseBufferOnPort(enum PortIndex portIndex, int bufferCount, int bufferSize)
{
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version = g_version;
        omxBuffer->bufferType = BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = OHOS::AshmemCreate(0, bufferSize);
        shared_ptr<OHOS::Ashmem> sharedMem = make_shared<OHOS::Ashmem>(fd, bufferSize);
        omxBuffer->bufferLen = sizeof(int);
        omxBuffer->buffer = (uint8_t*)(uintptr_t)fd;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;

        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            omxBuffer->type = READ_ONLY_TYPE;
            sharedMem->MapReadAndWriteAshmem();
        } else {
            omxBuffer->type = READ_WRITE_TYPE;
            sharedMem->MapReadOnlyAshmem();
        }
        auto err = g_component->UseBuffer(g_component, (uint32_t)portIndex, omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
            omxBuffer = nullptr;
            return false;
        }
        omxBuffer->bufferLen = 0;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

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
#endif  // COMPONENT_NAME
class CodecHdiOmxTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp()
    {}
    void TearDown()
    {}
};

static char arrayStr[ARRAY_TO_STR_LEN];
static char *GetArrayStr(int32_t *array, int32_t arrayLen, int32_t endValue)
{
    int32_t len = 0;
    int32_t totalLen = 0;
    int32_t ret;
    char value[INT_TO_STR_LEN];
    ret = memset_s(arrayStr, sizeof(arrayStr), 0, sizeof(arrayStr));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memset_s arrayStr failed, error code: %{public}d", __func__, ret);
        return arrayStr;
    }
    for (int32_t i = 0; i < arrayLen; i++) {
        if (array[i] == endValue) {
            break;
        }
        ret = memset_s(value, sizeof(value), 0, sizeof(value));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memset_s value failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        ret = sprintf_s(value, sizeof(value) - 1, "0x0%X, ", array[i]);
        if (ret < 0) {
            HDF_LOGE("%{public}s: sprintf_s value failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        len = strlen(value);
        ret = memcpy_s(arrayStr + totalLen, len, value, len);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s arrayStr failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        totalLen += len;
    }
    return arrayStr;
}

static void PrintCapability(CodecCompCapability *cap, int32_t index)
{
    HDF_LOGI("---------------------- component capability %{public}d ---------------------", index + 1);
    HDF_LOGI("role:%{public}d", cap->role);
    HDF_LOGI("type:%{public}d", cap->type);
    HDF_LOGI("compName:%{public}s", cap->compName);
    HDF_LOGI("supportProfiles:%{public}s", GetArrayStr(cap->supportProfiles, PROFILE_NUM, INVALID_PROFILE));
    HDF_LOGI("maxInst:%{public}d", cap->maxInst);
    HDF_LOGI("isSoftwareCodec:%{public}d", cap->isSoftwareCodec);
    HDF_LOGI("processModeMask:0x0%{public}x", cap->processModeMask);
    HDF_LOGI("capsMask:0x0%{public}x", cap->capsMask);
    HDF_LOGI("bitRate.min:%{public}d", cap->bitRate.min);
    HDF_LOGI("bitRate.max:%{public}d", cap->bitRate.max);
    if (strstr(cap->compName, "video") != NULL) {
        HDF_LOGI("minSize.width:%{public}d", cap->port.video.minSize.width);
        HDF_LOGI("minSize.height:%{public}d", cap->port.video.minSize.height);
        HDF_LOGI("maxSize.width:%{public}d", cap->port.video.maxSize.width);
        HDF_LOGI("maxSize.height:%{public}d", cap->port.video.maxSize.height);
        HDF_LOGI("widthAlignment:%{public}d", cap->port.video.whAlignment.widthAlignment);
        HDF_LOGI("heightAlignment:%{public}d", cap->port.video.whAlignment.heightAlignment);
        HDF_LOGI("blockCount.min:%{public}d", cap->port.video.blockCount.min);
        HDF_LOGI("blockCount.max:%{public}d", cap->port.video.blockCount.max);
        HDF_LOGI("blocksPerSecond.min:%{public}d", cap->port.video.blocksPerSecond.min);
        HDF_LOGI("blocksPerSecond.max:%{public}d", cap->port.video.blocksPerSecond.max);
        HDF_LOGI("blockSize.width:%{public}d", cap->port.video.blockSize.width);
        HDF_LOGI("blockSize.height:%{public}d", cap->port.video.blockSize.height);
        HDF_LOGI("supportPixFmts:%{public}s", GetArrayStr(cap->port.video.supportPixFmts, PIX_FORMAT_NUM, 0));
    } else {
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.sampleFormats, SAMPLE_FMT_NUM, AUDIO_SAMPLE_FMT_INVALID));
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.sampleRate, SAMPLE_RATE_NUM, AUD_SAMPLE_RATE_INVALID));
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.channelLayouts, CHANNEL_NUM, -1));
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.channelCount, CHANNEL_NUM, -1));
    }
    HDF_LOGI("-------------------------------------------------------------------");
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiInitTest_001, TestSize.Level1)
{
    const int32_t componentCount = 9;
    g_manager = GetCodecComponentManager();
    ASSERT_TRUE(g_manager != nullptr);

    g_count = g_manager->GetComponentNum();
    ASSERT_EQ(g_count, componentCount);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetCapabilityListTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_count > 0);
    ASSERT_TRUE(g_manager != nullptr);
    CodecCompCapability *capList = (CodecCompCapability *)OsalMemAlloc(sizeof(CodecCompCapability) * g_count);
    g_manager->GetComponentCapabilityList(capList, g_count);
    for (int32_t i = 0; i < g_count; i++) {
        PrintCapability(&capList[i], i);
    }
}

#ifdef COMPONENT_NAME
HWTEST_F(CodecHdiOmxTest, HdfCodecCreateComponentTest_001, TestSize.Level1)
{
    const int32_t testingAppData = 33;
    CodecCallbackType *callback = CodecCallbackTypeStubGetInstance();
    int32_t appData = testingAppData;
    int32_t ret = g_manager->CreateComponent(&g_component, const_cast<char *>(COMPONENT_NAME), &appData,
                                             sizeof(appData), callback);
    HDF_LOGE("%{public}s: after CreateComponent!", __func__);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_TRUE(g_component != nullptr);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetVersionTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    struct CompVerInfo verInfo;
    int32_t ret = g_component->GetComponentVersion(g_component, &verInfo);
    g_version = verInfo.compVersion;
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_STREQ(COMPONENT_NAME, verInfo.compName);
    HDF_LOGE("%{public}s: verInfo.compName is %{public}s!", __func__, verInfo.compName);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    auto ret = g_component->GetParameter(g_component, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// GetParameter with no version
HWTEST_F(CodecHdiOmxTest, HdfCodecGetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    memset_s(&param, sizeof(param), 0, sizeof(param));
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    auto ret = g_component->GetParameter(g_component, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecSetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    int32_t ret = g_component->SetParameter(g_component, OMX_IndexParamVideoPortFormat,
                                            reinterpret_cast<int8_t *>(&param), sizeof(param));
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// SetParameter with no version
HWTEST_F(CodecHdiOmxTest, HdfCodecSetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    memset_s(&param, sizeof(param), 0, sizeof(param));
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    int32_t ret = g_component->SetParameter(g_component, OMX_IndexParamVideoPortFormat,
                                            reinterpret_cast<int8_t *>(&param), sizeof(param));
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    int32_t ret = g_component->GetConfig(g_component, OMX_IndexConfigVideoBitrate, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecSetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    param.nEncodeBitrate = FRAMERATE;
    int32_t ret = g_component->SetConfig(g_component, OMX_IndexConfigVideoBitrate, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// GetConfig error
HWTEST_F(CodecHdiOmxTest, HdfCodecGetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    int32_t ret = g_component->GetConfig(g_component, OMX_IndexConfigVideoBitrate, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_NE(ret, HDF_SUCCESS);
}

// SetConfig with no version
HWTEST_F(CodecHdiOmxTest, HdfCodecSetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    param.nEncodeBitrate = FRAMERATE;
    int32_t ret = g_component->SetConfig(g_component, OMX_IndexConfigVideoBitrate, reinterpret_cast<int8_t *>(&param),
                                         sizeof(param));
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetExtensionIndexTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_INDEXTYPE indexType;
    int32_t ret =
        g_component->GetExtensionIndex(g_component, "OMX.Topaz.index.param.extended_video", (uint32_t *)&indexType);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecGetStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_STATETYPE state;
    int32_t ret = g_component->GetState(g_component, &state);
    ASSERT_EQ(state, OMX_StateLoaded);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecTunnelRequestTestTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    const int32_t tunneledComp = 1002;
    const uint32_t tunneledPort = 101;
    OMX_TUNNELSETUPTYPE tunnelSetup;
    tunnelSetup.eSupplier = OMX_BufferSupplyInput;

    int32_t ret = g_component->ComponentTunnelRequest(g_component, (uint32_t)PortIndex::PORT_INDEX_OUTPUT, tunneledComp,
                                                      tunneledPort, &tunnelSetup);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// send command to Idle buffer allocate and usebuffer
HWTEST_F(CodecHdiOmxTest, HdfCodecToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->SendCommand(g_component, OMX_CommandStateSet, OMX_StateIdle, nullptr, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_STATETYPE state;
    ret = g_component->GetState(g_component, &state);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Use buffer on input index
HWTEST_F(CodecHdiOmxTest, HdfCodecUseBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_INPUT;
    auto err = g_component->GetParameter(g_component, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    ASSERT_EQ(err, HDF_SUCCESS);

    int bufferSize = param.nBufferSize;
    int bufferCount = param.nBufferCountActual;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, bufferCount, bufferSize);
    ASSERT_TRUE(ret);
}

// Use Buffer on output index
HWTEST_F(CodecHdiOmxTest, HdfCodecUseBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_OUTPUT;
    auto err = g_component->GetParameter(g_component, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    ASSERT_EQ(err, HDF_SUCCESS);

    int bufferSize = param.nBufferSize;
    int bufferCount = param.nBufferCountActual;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, bufferCount, bufferSize);
    ASSERT_TRUE(ret);
}

// Use buffer on input index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxTest, HdfCodecUseBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_INPUT;
    auto err = g_component->GetParameter(g_component, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    ASSERT_EQ(err, HDF_SUCCESS);

    int bufferSize = param.nBufferSize;
    int bufferCount = 1;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, bufferCount, bufferSize);
    ASSERT_FALSE(ret);
}
// Use buffer on output index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxTest, HdfCodecUseBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)PortIndex::PORT_INDEX_OUTPUT;
    auto err = g_component->GetParameter(g_component, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    ASSERT_EQ(err, HDF_SUCCESS);

    int bufferSize = param.nBufferSize;
    int bufferCount = 1;
    bool ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, bufferCount, bufferSize);
    ASSERT_FALSE(ret);
}

struct OmxCodecBuffer allocBuffer;
HWTEST_F(CodecHdiOmxTest, HdfCodecAllocateBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    // buffer is full
    allocBuffer.fenceFd = -1;
    allocBuffer.version = g_version;
    allocBuffer.bufferType = BUFFER_TYPE_AVSHARE_MEM_FD;
    allocBuffer.allocLen = BUFFER_SIZE;
    allocBuffer.buffer = 0;
    allocBuffer.bufferLen = 0;
    allocBuffer.pts = 0;
    allocBuffer.flag = 0;
    allocBuffer.type = READ_ONLY_TYPE;
    int32_t ret = g_component->AllocateBuffer(g_component, (uint32_t)PortIndex::PORT_INDEX_INPUT, &allocBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecUseEglImageTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    // buffer is full
    struct OmxCodecBuffer buffer;
    buffer.fenceFd = -1;
    buffer.version = g_version;
    buffer.bufferType = BUFFER_TYPE_AVSHARE_MEM_FD;
    buffer.allocLen = BUFFER_SIZE;
    buffer.buffer = 0;
    buffer.bufferLen = 0;
    buffer.pts = 0;
    buffer.flag = 0;
    buffer.type = READ_ONLY_TYPE;
    auto eglImage = std::make_unique<int8_t[]>(BUFFER_SIZE);
    int32_t ret = g_component->UseEglImage(g_component, &buffer, (uint32_t)PortIndex::PORT_INDEX_INPUT, eglImage.get(),
                                           BUFFER_SIZE);
    ASSERT_NE(ret, HDF_SUCCESS);
    eglImage = nullptr;
}

HWTEST_F(CodecHdiOmxTest, HdfCodecWaitStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    // wait for Idle status
    OMX_STATETYPE state = OMX_StateInvalid;
    do {
        usleep(100);
        auto ret = g_component->GetState(g_component, &state);
        ASSERT_EQ(ret, HDF_SUCCESS);
    } while (state != OMX_StateIdle);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecFillThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->SendCommand(g_component, OMX_CommandStateSet, OMX_StateExecuting, nullptr, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
    OMX_STATETYPE state = OMX_StateInvalid;
    do {
        ret = g_component->GetState(g_component, &state);
        ASSERT_EQ(ret, HDF_SUCCESS);
        usleep(100);
    } while (state != OMX_StateExecuting);

    // fill this buffer need OMX_StateExecuting
    auto iter = outputBuffers.begin();
    if (iter != outputBuffers.end()) {
        int32_t ret = g_component->FillThisBuffer(g_component, iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecEmptyThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    if (iter != inputBuffers.end()) {
        int32_t ret = g_component->EmptyThisBuffer(g_component, iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

HWTEST_F(CodecHdiOmxTest, HdfCodecSetCallbackTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    const int32_t appDataLen = 10;
    CodecCallbackType *callback = CodecCallbackTypeStubGetInstance();
    int8_t appData[appDataLen];
    for (int8_t i = 0; i < appDataLen; i++) {
        appData[i] = i;
    }
    int32_t ret = g_component->SetCallbacks(g_component, callback, appData, (uint32_t)appDataLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecRoleEnumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    uint8_t role[ROLE_LEN] = {0};
    int32_t ret = g_component->ComponentRoleEnum(g_component, role, ROLE_LEN, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Executing to Idle
HWTEST_F(CodecHdiOmxTest, HdfCodecExecutingToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->SendCommand(g_component, OMX_CommandStateSet, OMX_StateIdle, nullptr, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Release input buffer
HWTEST_F(CodecHdiOmxTest, HdfCodecFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = outputBuffers.begin();
    while (iter != outputBuffers.end()) {
        int32_t ret =
            g_component->FreeBuffer(g_component, (uint32_t)PortIndex::PORT_INDEX_OUTPUT, iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
        iter = outputBuffers.erase(iter);
    }
}

// Release input buffer
HWTEST_F(CodecHdiOmxTest, HdfCodecFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    auto iter = inputBuffers.begin();
    while (iter != inputBuffers.end()) {
        int32_t ret =
            g_component->FreeBuffer(g_component, (uint32_t)PortIndex::PORT_INDEX_INPUT, iter->second->omxBuffer.get());
        ASSERT_EQ(ret, HDF_SUCCESS);
        iter = inputBuffers.erase(iter);
    }
}

// When ComponentDeInit, must change to Loaded State
HWTEST_F(CodecHdiOmxTest, HdfCodecIdleToLoadedTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->SendCommand(g_component, OMX_CommandStateSet, OMX_StateLoaded, nullptr, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
    // State changed OMX_StateIdle when release all this buffer
    OMX_STATETYPE state = OMX_StateInvalid;
    do {
        usleep(100);
        auto ret = g_component->GetState(g_component, &state);
        ASSERT_EQ(ret, HDF_SUCCESS);
    } while (state != OMX_StateLoaded);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecDeInitTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t ret = g_component->ComponentDeInit(g_component);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecDestoryComponentTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    ASSERT_TRUE(g_manager != nullptr);
    int ret = g_manager->DestoryComponent(g_component);
    ASSERT_EQ(ret, HDF_SUCCESS);
    CodecComponentManagerRelease();
}
#endif  // COMPONENT_NAME
}  // namespace
