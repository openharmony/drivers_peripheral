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

#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Video.h>
#include <OMX_VideoExt.h>
#include <gtest/gtest.h>
#include <hdf_log.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <vector>
#include <benchmark/benchmark.h>
#include "codec_omx_ext.h"
#include "v4_0/codec_callback_service.h"
#include "v4_0/icodec_component.h"
#include "v4_0/icodec_component_manager.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

#define HDF_LOG_TAG codec_benchmark_omx_test
#define CODEC_NUM 0
#define TUNNELE_COMP 1002
#define TUNNELED_PORT 101

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace OHOS::HDI::Codec::V4_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
namespace {
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;
constexpr int32_t WIDTH = 640;
constexpr int FD_DEFAULT = -1;
constexpr int64_t APP_DATA = 3;
constexpr int32_t HEIGHT = 480;
constexpr int32_t BUFFER_SIZE = WIDTH * HEIGHT * 3;
constexpr int32_t FRAMERATE = 30 << 16;
constexpr uint32_t BUFFER_ID_ERROR = 65000;
static IDisplayBuffer *gralloc_ = nullptr;
static sptr<ICodecComponent> component_ = nullptr;
static sptr<ICodecCallback> callback_ = nullptr;
static sptr<ICodecComponentManager> manager_ = nullptr;
static OHOS::HDI::Codec::V4_0::CodecVersionType version_;
static inline std::string compName_ = "";

class CodecBenchmarkOmxTest : public benchmark::Fixture {
public:
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
            if (bufferHandle != nullptr && gralloc_ != nullptr) {
                gralloc_->FreeMem(*bufferHandle);
                bufferHandle = nullptr;
            }
        }
    };
    template <typename T>
    void InitParam(T &param)
    {
        int32_t ret = memset_s(&param, sizeof(param), 0, sizeof(param));
        ASSERT_EQ(ret, EOK);
        param.nSize = sizeof(param);
        param.nVersion.nVersion = 1;
    }

    template <typename T>
    void InitExtParam(T &param)
    {
        int32_t ret = memset_s(&param, sizeof(param), 0, sizeof(param));
        ASSERT_EQ(ret, EOK);
        param.size = sizeof(param);
        param.version.nVersion = 1;
    }

    void InitOmxCodecBuffer(OmxCodecBuffer& buffer, CodecBufferType type)
    {
        buffer.bufferType = type;
        buffer.fenceFd = -1;
        buffer.version = version_;
        buffer.allocLen = BUFFER_SIZE;
        buffer.fd = FD_DEFAULT;
        buffer.bufferhandle = nullptr;
        buffer.pts = CODEC_NUM;
        buffer.flag = CODEC_NUM;
        buffer.size = sizeof(OmxCodecBuffer);
        buffer.type = READ_ONLY_TYPE;
    }

    void InitCodecBufferWithAshMem(enum PortIndex port, int bufferSize, shared_ptr<OmxCodecBuffer> omxBuffer,
                                   shared_ptr<OHOS::Ashmem> sharedMem)
    {
        InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
        omxBuffer->fd = sharedMem->GetAshmemFd();
        if (port == PortIndex::PORT_INDEX_INPUT) {
            omxBuffer->type = READ_ONLY_TYPE;
            sharedMem->MapReadAndWriteAshmem();
        } else {
            omxBuffer->type = READ_WRITE_TYPE;
            sharedMem->MapReadOnlyAshmem();
        }
    }

    bool UseBufferOnPort(enum PortIndex port, int32_t bufferCount, int32_t bufferSize)
    {
        for (int i = 0; i < bufferCount; i++) {
            std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
            if (omxBuffer == nullptr) {
                return false;
            }

            int fd = OHOS::AshmemCreate(CODEC_NUM, bufferSize);
            shared_ptr<OHOS::Ashmem> sharedMem = make_shared<OHOS::Ashmem>(fd, bufferSize);
            if (sharedMem == nullptr) {
                if (fd >= 0) {
                    close(fd);
                    fd = -1;
                }
                return false;
            }
            InitCodecBufferWithAshMem(port, bufferSize, omxBuffer, sharedMem);
            OmxCodecBuffer outBuffer;
            auto err = component_->UseBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
            if (err != HDF_SUCCESS) {
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
            if (port == PortIndex::PORT_INDEX_INPUT) {
                inputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
            } else {
                outputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
            }
        }
        return true;
    }

    bool FreeBufferOnPort(enum PortIndex port)
    {
        std::map<int32_t, std::shared_ptr<BufferInfo>> &buffer = inputBuffers_;
        if (port == PortIndex::PORT_INDEX_OUTPUT) {
            buffer = outputBuffers_;
        }
        for (auto [bufferId, bufferInfo] : buffer) {
            auto ret = component_->FreeBuffer(static_cast<uint32_t>(port), *bufferInfo->omxBuffer.get());
            if (ret != HDF_SUCCESS) {
                return false;
            }
        }
        buffer.clear();
        return true;
    }

    void InitComponent()
    {
        int32_t count = CODEC_NUM;
        (void)manager_->GetComponentNum(count);
        if (count > 0) {
            std::vector<CodecCompCapability> capList;
            auto err = manager_->GetComponentCapabilityList(capList, count);
            ASSERT_TRUE(err == HDF_SUCCESS);
            compName_ = capList[0].compName;
        }

        callback_ = new CodecCallbackService();
        if (callback_ == nullptr) {
            return;
        }
        if (compName_.empty()) {
            return;
        }

        auto ret = manager_->CreateComponent(component_, componentId_, compName_.data(),
                                             APP_DATA, callback_);
        ASSERT_TRUE(component_ != nullptr);
        if (ret != HDF_SUCCESS) {
            return;
        }
        struct CompVerInfo verInfo;
        ret = component_->GetComponentVersion(verInfo);
        ASSERT_TRUE(component_ != nullptr);
        if (ret != HDF_SUCCESS) {
            return;
        }
        version_ = verInfo.compVersion;
        return;
    }

    void SetUp(benchmark::State &state)
    {
        manager_ = ICodecComponentManager::Get();
        gralloc_ = IDisplayBuffer::Get();
        if (manager_ == nullptr || gralloc_ == nullptr) {
            std::cout << "GetCodecComponentManager  or GetDisplayBuffer ret nullptr" << std::endl;
            return;
        }
        InitComponent();
    }

    void TearDown(benchmark::State &state)
    {
        if (manager_ != nullptr && component_ != nullptr) {
            manager_->DestroyComponent(componentId_);
        }
        component_ = nullptr;
        callback_ = nullptr;
        manager_ = nullptr;
        gralloc_ = nullptr;
    }

public:
    uint32_t componentId_ = CODEC_NUM;
    std::map<int32_t, std::shared_ptr<BufferInfo>> inputBuffers_;
    std::map<int32_t, std::shared_ptr<BufferInfo>> outputBuffers_;
    const static uint32_t inputIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    const static uint32_t outputIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
};

template <typename T>
void ObjectToVector(T &param, std::vector<int8_t> &vec)
{
    int8_t *paramPointer = reinterpret_cast<int8_t *>(&param);
    vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
}

BENCHMARK_F(CodecBenchmarkOmxTest, GetComponentVersion)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    struct CompVerInfo verInfo;
    for (auto _ : state) {
        ret = component_->GetComponentVersion(verInfo);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, GetComponentVersion)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, GetParameter)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    CodecVideoPortFormatParam pixFormat;
    InitExtParam(pixFormat);
    pixFormat.portIndex = outputIndex;
    pixFormat.codecColorIndex = CODEC_NUM;

    std::vector<int8_t> inParam;
    ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    for (auto _ : state) {
        ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, GetParameter)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, SetParameter)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    for (auto _ : state) {
        ret = component_->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, SetParameter)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, GetConfig)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    for (auto _ : state) {
        ret = component_->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, GetConfig)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, SetConfig)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;
    param.nEncodeBitrate = FRAMERATE;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    for (auto _ : state) {
        ret = component_->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, SetConfig)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

#ifdef SUPPORT_OMX_EXTEND
BENCHMARK_F(CodecBenchmarkOmxTest, GetExtensionIndex)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    uint32_t indexType = CODEC_NUM;
    for (auto _ : state) {
        ret = component_->GetExtensionIndex("OMX.Topaz.index.param.extended_video", indexType);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, GetExtensionIndex)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
#endif

BENCHMARK_F(CodecBenchmarkOmxTest, GetState)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    CodecStateType codecState = CODEC_STATE_INVALID;
    for (auto _ : state) {
        ret = component_->GetState(codecState);
        ASSERT_EQ(codecState, CODEC_STATE_LOADED);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, GetState)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

#ifdef SUPPORT_OMX_EXTEND
BENCHMARK_F(CodecBenchmarkOmxTest, ComponentTunnelRequest)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    const int32_t tunneledComp = TUNNELE_COMP;
    const uint32_t tunneledPort = TUNNELED_PORT;
    OHOS::HDI::Codec::V4_0::CodecTunnelSetupType tunnelSetup;
    tunnelSetup.supplier = OHOS::HDI::Codec::V4_0::CODEC_BUFFER_SUPPLY_INPUT;
    for (auto _ : state) {
    ret = component_->ComponentTunnelRequest(outputIndex, tunneledComp, tunneledPort,
        tunnelSetup, tunnelSetup);
        ASSERT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, ComponentTunnelRequest)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, SendCommand)(benchmark::State &state)
{
    std::vector<int8_t> cmdData;
    int32_t ret;
    for (auto _ : state) {
        if (component_ == nullptr) {
            InitComponent();
        }
        ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
        manager_->DestroyComponent(componentId_);
        ASSERT_EQ(ret, HDF_SUCCESS);
        component_ = nullptr;
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, SendCommand)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, AllocateBuffer)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto err = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    allocBuffer.type = READ_WRITE_TYPE;
    struct OmxCodecBuffer outBuffer;
    for (auto _ : state) {
        err = component_->AllocateBuffer(outputIndex, allocBuffer, outBuffer);
        ASSERT_EQ(err, HDF_SUCCESS);
        err = component_->FreeBuffer(outputIndex, outBuffer);
        ASSERT_EQ(err, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, AllocateBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, UseBuffer)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    AllocInfo alloc = {.width = WIDTH,
                       .height = HEIGHT,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};
    BufferHandle *bufferHandle = nullptr;
    ASSERT_TRUE(gralloc_ != nullptr);
    ret = gralloc_->AllocMem(alloc, bufferHandle);
    ASSERT_EQ(ret, DISPLAY_SUCCESS);
 
    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    size_t handleSize =
        sizeof(BufferHandle) + (sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts));
    InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_HANDLE);
    omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    omxBuffer->allocLen = handleSize;
    OmxCodecBuffer outBuffer;
    for (auto _ : state) {
        ret = component_->UseBuffer(inputIndex, *omxBuffer.get(), outBuffer);
        omxBuffer->bufferId = outBuffer.bufferId;
        ASSERT_EQ(ret, HDF_SUCCESS);
        ret = component_->FreeBuffer(inputIndex, outBuffer);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, UseBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
#endif

BENCHMARK_F(CodecBenchmarkOmxTest, UseEglImage)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    auto eglImage = std::make_unique<int8_t[]>(BUFFER_SIZE);
    ASSERT_TRUE(eglImage != nullptr);
    std::vector<int8_t> eglImageVec;
    eglImageVec.assign(eglImage.get(), eglImage.get() + BUFFER_SIZE);
    struct OmxCodecBuffer outbuffer;
    for (auto _ : state) {
        ret = component_->UseEglImage(inputIndex, omxBuffer, outbuffer, eglImageVec);
        ASSERT_NE(ret, HDF_SUCCESS);
        eglImage = nullptr;
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, UseEglImage)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, FillThisBuffer)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    for (auto _ : state) {
        ret = component_->FillThisBuffer(omxBuffer);
        ASSERT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, FillThisBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, EmptyThisBuffer)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    for (auto _ : state) {
        ret = component_->EmptyThisBuffer(omxBuffer);
        ASSERT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, EmptyThisBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, SetCallbacks)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    callback_ = new CodecCallbackService();
    ASSERT_TRUE(callback_ != nullptr);
    for (auto _ : state) {
        ret = component_->SetCallbacks(callback_, APP_DATA);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, SetCallbacks)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

#ifdef SUPPORT_OMX_EXTEND
BENCHMARK_F(CodecBenchmarkOmxTest, ComponentRoleEnum)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    int32_t ret;
    std::vector<uint8_t> role;
    for (auto _ : state) {
        ret = component_->ComponentRoleEnum(role, CODEC_NUM);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, ComponentRoleEnum)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, FreeBuffer)(benchmark::State &state)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto err = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    allocBuffer.type = READ_WRITE_TYPE;
    struct OmxCodecBuffer outBuffer;
    for (auto _ : state) {
        err = component_->AllocateBuffer(outputIndex, allocBuffer, outBuffer);
        ASSERT_EQ(err, HDF_SUCCESS);
        err = component_->FreeBuffer(outputIndex, outBuffer);
        ASSERT_EQ(err, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, FreeBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(CodecBenchmarkOmxTest, ComponentDeInit)(benchmark::State &state)
{
    std::vector<int8_t> cmdData;
    int32_t ret;
    for (auto _ : state) {
        if (component_ == nullptr) {
            InitComponent();
        }
        ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
        ASSERT_EQ(ret, HDF_SUCCESS);
        CodecStateType state = CODEC_STATE_INVALID;
        do {
            usleep(ITERATION_FREQUENCY);
            ret = component_->GetState(state);
        } while (state != CODEC_STATE_LOADED);
        ret = component_->ComponentDeInit();
        if (manager_ != nullptr && component_ != nullptr) {
            manager_->DestroyComponent(componentId_);
        }
        component_ = nullptr;
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(CodecBenchmarkOmxTest, ComponentDeInit)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
#endif
}  // namespace
BENCHMARK_MAIN();
