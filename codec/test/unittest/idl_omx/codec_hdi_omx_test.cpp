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

#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Video.h>
#include <OMX_VideoExt.h>
#include <gtest/gtest.h>
#include <hdf_log.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <vector>
#include "codec_omx_ext.h"
#include "v1_0/codec_callback_service.h"
#include "v1_0/icodec_component.h"
#include "v1_0/icodec_component_manager.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

#define HDF_LOG_TAG codec_hdi_test

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace OHOS::HDI::Codec::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
namespace {
constexpr int32_t WIDTH = 640;
constexpr uint32_t MAX_ROLE_INDEX = 256;
constexpr int FD_DEFAULT = -1;
constexpr int64_t APP_DATA = 3;
constexpr int32_t HEIGHT = 480;
constexpr int32_t BUFFER_SIZE = WIDTH * HEIGHT * 3;
constexpr int32_t FRAMERATE = 30 << 16;
constexpr uint32_t BUFFER_ID_ERROR = 65000;
constexpr uint32_t WAIT_TIME = 1000;
constexpr uint32_t MAX_WAIT = 50;
constexpr uint32_t DENOMINATOR = 2;
constexpr uint32_t NUMERATOR = 3;
constexpr uint32_t ALIGNMENT = 16;
constexpr uint32_t ERROR_FENCEFD = 1;
constexpr AvCodecRole ROLE = MEDIA_ROLETYPE_VIDEO_AVC;

static IDisplayBuffer *gralloc_ = nullptr;
static sptr<ICodecComponent> component_ = nullptr;
static sptr<ICodecCallback> callback_ = nullptr;
static sptr<ICodecComponentManager> manager_ = nullptr;
static OHOS::HDI::Codec::V1_0::OMX_VERSIONTYPE version_;
static inline std::string compName_ = "";

template <typename T>
void ObjectToVector(T &param, std::vector<int8_t> &vec)
{
    int8_t *paramPointer = (int8_t *)&param;
    vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
}

template <typename T>
int32_t VectorToObject(std::vector<int8_t> &vec, T &param)
{
    auto ret = memcpy_s(&param, sizeof(param), vec.data(), vec.size());
    if (ret != EOK) {
        HDF_LOGE("%{public}s error, memset_s ret [%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    vec.clear();
    return HDF_SUCCESS;
}

class CodecHdiOmxTest : public testing::Test {
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
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.nSize = sizeof(param);
        param.nVersion.nVersion = 1;
    }

    template <typename T>
    void InitExtParam(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.size = sizeof(param);
        param.version.nVersion = 1;
    }

    void InitOmxCodecBuffer(OmxCodecBuffer &buffer, CodecBufferType type)
    {
        buffer.bufferType = type;
        buffer.fenceFd = ERROR_FENCEFD;
        buffer.version = version_;
        buffer.allocLen = BUFFER_SIZE;
        buffer.fd = FD_DEFAULT;
        buffer.bufferhandle = nullptr;
        buffer.pts = 0;
        buffer.flag = 0;
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

    uint32_t AlignUp(uint32_t width)
    {
        return (((width) + ALIGNMENT - 1) & (~(ALIGNMENT - 1)));
    }

    void InitBufferHandleParameter(OMX_PARAM_PORTDEFINITIONTYPE &param)
    {
        InitParam(param);
        param.nPortIndex = inputIndex;
        std::vector<int8_t> inParam, outParam;
        ObjectToVector(param, inParam);
        auto ret = component_->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
        ASSERT_EQ(ret, HDF_SUCCESS);

        VectorToObject(outParam, param);
        param.format.video.nFrameWidth = WIDTH;
        param.format.video.nFrameHeight = HEIGHT;
        param.format.video.nStride = AlignUp(WIDTH);
        param.format.video.nSliceHeight = HEIGHT;
        param.format.video.eColorFormat = OMX_COLOR_FormatYUV420SemiPlanar;
        std::vector<int8_t> enc;
        ObjectToVector(param, enc);
        ret = component_->SetParameter(OMX_IndexParamPortDefinition, enc);
        ASSERT_EQ(ret, HDF_SUCCESS);

        std::vector<int8_t> data;
        UseBufferType type;
        type.size = sizeof(UseBufferType);
        type.version.s.nVersionMajor = 1;
        type.portIndex = inputIndex;
        type.bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
        ObjectToVector(type, data);
        ret = component_->SetParameter(OMX_IndexParamUseBufferType, data);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }

    void FillCodecBufferWithBufferHandle(shared_ptr<OmxCodecBuffer> omxBuffer)
    {
        AllocInfo alloc = {.width = WIDTH,
                           .height = HEIGHT,
                           .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                           .format = PIXEL_FMT_YCBCR_420_SP};

        BufferHandle *bufferHandle = nullptr;
        ASSERT_TRUE(gralloc_ != nullptr);
        auto ret = gralloc_->AllocMem(alloc, bufferHandle);
        ASSERT_EQ(ret, HDF_SUCCESS);
        omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    }

    bool UseDynaBuffer(enum PortIndex port, int bufferCount, int bufferSize)
    {
        if (bufferCount <= 0 || bufferSize <= 0) {
            return false;
        }

        for (int i = 0; i < bufferCount; i++) {
            auto omxBuffer = std::make_shared<OmxCodecBuffer>();
            InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);
            omxBuffer->allocLen = WIDTH * HEIGHT * NUMERATOR / DENOMINATOR;

            OmxCodecBuffer outBuffer;
            auto ret = component_->UseBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
            if (ret != HDF_SUCCESS) {
                return false;
            }

            omxBuffer->bufferId = outBuffer.bufferId;
            auto bufferInfo = std::make_shared<BufferInfo>();
            bufferInfo->omxBuffer = omxBuffer;
            inputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        }
        return true;
    }

    bool UseBufferOnPort(enum PortIndex port, int32_t bufferCount, int32_t bufferSize)
    {
        for (int i = 0; i < bufferCount; i++) {
            std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
            if (omxBuffer == nullptr) {
                return false;
            }

            int fd = OHOS::AshmemCreate(0, bufferSize);
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

    bool AllocateBufferOnPort(enum PortIndex port, int32_t bufferCount, int32_t bufferSize)
    {
        for (int i = 0; i < bufferCount; i++) {
            std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
            if (omxBuffer == nullptr) {
                return false;
            }

            int fd = OHOS::AshmemCreate(0, bufferSize);
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
            auto err = component_->AllocateBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
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

    int32_t GetPortParameter(PortIndex index, OMX_PARAM_PORTDEFINITIONTYPE &param)
    {
        InitParam(param);
        param.nPortIndex = static_cast<OMX_U32>(index);
        std::vector<int8_t> inParam;
        ObjectToVector(param, inParam);

        std::vector<int8_t> outParam;
        auto ret = component_->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
        VectorToObject(outParam, param);
        return ret;
    }

    void FillAndEmptyAllBuffer(CodecBufferType type)
    {
        auto iter = outputBuffers_.begin();
        if (iter != outputBuffers_.end()) {
            auto ret = component_->FillThisBuffer(*iter->second->omxBuffer.get());
            ASSERT_EQ(ret, HDF_SUCCESS);
        }
        iter = inputBuffers_.begin();
        if (iter != inputBuffers_.end()) {
            if (type == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE) {
                FillCodecBufferWithBufferHandle(iter->second->omxBuffer);
            }
            auto ret = component_->EmptyThisBuffer(*iter->second->omxBuffer.get());
            ASSERT_EQ(ret, HDF_SUCCESS);
        }
    }

    void WaitState(CodecStateType objState)
    {
        CodecStateType state = CODEC_STATE_INVALID;
        uint32_t count = 0;
        do {
            usleep(WAIT_TIME);
            auto ret = component_->GetState(state);
            ASSERT_EQ(ret, HDF_SUCCESS);
            count++;
        } while (state != objState && count <= MAX_WAIT);
    }

    static void SetUpTestCase()
    {
        manager_ = ICodecComponentManager::Get();
        gralloc_ = IDisplayBuffer::Get();
        if (manager_ == nullptr) {
            std::cout<<"GetCodecComponentManager ret nullptr"<<std::endl;
            return;
        }
        int32_t count = 0;
        (void)manager_->GetComponentNum(count);
        if (count > 0) {
            std::vector<CodecCompCapability> capList;
            auto err = manager_->GetComponentCapabilityList(capList, count);
            ASSERT_TRUE(err == HDF_SUCCESS);
            for (auto cap : capList) {
                if (cap.type == CodecType::VIDEO_ENCODER && cap.role == ROLE) {
                    compName_ = cap.compName;
                    break;
                }
            }
        }
    }
    static void TearDownTestCase()
    {
        manager_ = nullptr;
        gralloc_ = nullptr;
    }
    void SetUp()
    {
        if (manager_ == nullptr) {
            return;
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
        if (ret != HDF_SUCCESS) {
            return;
        }
        struct CompVerInfo verInfo;
        ret = component_->GetComponentVersion(verInfo);
        if (ret != HDF_SUCCESS) {
            return;
        }
        version_ = verInfo.compVersion;
    }
    void TearDown()
    {
        std::vector<int8_t> cmdData;
        auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
        if (ret != HDF_SUCCESS) {
            std::cout<<"SendCommand CODEC_STATE_LOADED error"<<std::endl;
        }
        if (manager_ != nullptr && component_ != nullptr) {
            manager_->DestoryComponent(componentId_);
        }
        component_ = nullptr;
        callback_ = nullptr;
    }

public:
    uint32_t componentId_ = 0;
    std::map<int32_t, std::shared_ptr<BufferInfo>> inputBuffers_;
    std::map<int32_t, std::shared_ptr<BufferInfo>> outputBuffers_;
    const static uint32_t inputIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    const static uint32_t outputIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
};

// Test GetComponentVersion
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetVersionTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct CompVerInfo verInfo;
    auto ret = component_->GetComponentVersion(verInfo);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    CodecVideoPortFormatParam pixFormat;
    InitExtParam(pixFormat);
    pixFormat.portIndex = outputIndex;
    pixFormat.codecColorIndex = 0;

    std::vector<int8_t> inParam;
    ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    CodecVideoPortFormatParam pixFormat;
    InitExtParam(pixFormat);
    pixFormat.portIndex = inputIndex;
    pixFormat.codecColorIndex = 0;

    std::vector<int8_t> inParam;
    ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Test GetParameter
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> inParam;
    std::vector <int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexParamVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    memset_s(&param, sizeof(param), 0, sizeof(param));
    param.nPortIndex = inputIndex;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_006, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetParameterTest_007, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexVideoStartUnused, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    auto ret = component_->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    memset_s(&param, sizeof(param), 0, sizeof(param));
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    auto ret = component_->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> paramVec;
    auto ret = component_->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    auto ret = component_->SetParameter(OMX_IndexParamVideoPortFormat, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_005, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    std::vector<int8_t> paramVec;
    ObjectToVector(param, paramVec);
    auto ret = component_->SetParameter(OMX_IndexVideoStartUnused, paramVec);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetParameterTest_006, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    CodecVideoPortFormatParam pixFormat;
    InitExtParam(pixFormat);
    pixFormat.portIndex = inputIndex;
    pixFormat.codecColorIndex = 0;
    std::vector<int8_t> inParam;
    ObjectToVector(pixFormat, inParam);

    std::vector<int8_t> outParam;
    auto ret = component_->GetParameter(OMX_IndexCodecVideoPortFormat, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);

    pixFormat.codecColorFormat = PIXEL_FMT_YCBCR_420_SP;
    std::vector<int8_t> paramVec;
    ObjectToVector(pixFormat, paramVec);
    ret = component_->SetParameter(OMX_IndexCodecVideoPortFormat, paramVec);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Test GetConfig
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = component_->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = component_->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> inParam;
    std::vector<int8_t> outParam;
    auto ret = component_->GetConfig(OMX_IndexConfigVideoBitrate, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    std::vector<int8_t> outParam;
    auto ret = component_->GetConfig(OMX_IndexVideoStartUnused, inParam, outParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Test SetConfig
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;
    param.nEncodeBitrate = FRAMERATE;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    auto ret = component_->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = inputIndex;
    param.nEncodeBitrate = FRAMERATE;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    auto ret = component_->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> inParam;
    auto ret = component_->SetConfig(OMX_IndexConfigVideoBitrate, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetConfigTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    OMX_VIDEO_CONFIG_BITRATETYPE param;
    InitParam(param);
    param.nPortIndex = outputIndex;

    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);
    auto ret = component_->SetConfig(OMX_IndexVideoStartUnused, inParam);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Test GetExtensionIndex
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetExtensionIndexTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    uint32_t indexType = 0;
    auto ret = component_->GetExtensionIndex("OMX.Topaz.index.param.extended_video", indexType);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetExtensionIndexTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    uint32_t indexType = 0;
    auto ret = component_->GetExtensionIndex("OMX.Topaz.index.param.extended_test", indexType);
    ASSERT_NE(ret, HDF_SUCCESS);
}


// Test GetState
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiGetStateTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    CodecStateType state = CODEC_STATE_INVALID;
    int32_t ret = component_->GetState(state);
    ASSERT_EQ(state, CODEC_STATE_LOADED);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Test ComponentTunnelRequest
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiTunnelRequestTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    const int32_t tunneledComp = 1002;
    const uint32_t tunneledPort = 101;
    OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE tunnelSetup;
    tunnelSetup.eSupplier = OHOS::HDI::Codec::V1_0::OMX_BufferSupplyInput;

    auto ret = component_->ComponentTunnelRequest(outputIndex, tunneledComp, tunneledPort,
        tunnelSetup, tunnelSetup);
    ASSERT_NE(ret, HDF_SUCCESS);
}
#endif

#ifdef SUPPORT_OMX_EXTEND
// Test SendCommand
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiLoadedToIdleTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferAndFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto err = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    struct OmxCodecBuffer outBuffer;
    err = component_->AllocateBuffer(inputIndex, allocBuffer, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);

    err = component_->FreeBuffer(inputIndex, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiAllocateBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto err = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(err, HDF_SUCCESS);

    struct OmxCodecBuffer allocBuffer;
    InitOmxCodecBuffer(allocBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    allocBuffer.type = READ_WRITE_TYPE;
    struct OmxCodecBuffer outBuffer;
    err = component_->AllocateBuffer(outputIndex, allocBuffer, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);

    err = component_->FreeBuffer(outputIndex, outBuffer);
    ASSERT_EQ(err, HDF_SUCCESS);
}
#endif

// Test UseBuffer
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->UseBuffer(inputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_INVALID);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->UseBuffer(outputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->UseBuffer(inputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_VIRTUAL_ADDR);
    struct OmxCodecBuffer outBuffer;
    auto ret = component_->UseBuffer(outputIndex, omxBuffer, outBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// Use buffer on input index
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_INPUT, param);

    auto err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_HANDLE);
    FillCodecBufferWithBufferHandle(omxBuffer);
    OmxCodecBuffer outBuffer;

    ret = component_->UseBuffer(inputIndex, *omxBuffer.get(), outBuffer);
    omxBuffer->bufferId = outBuffer.bufferId;
    ASSERT_EQ(ret, HDF_SUCCESS);
    ret = component_->FreeBuffer(inputIndex, outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Use Buffer on output index
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_OUTPUT, param);

    auto err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_004, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
    InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);

    OmxCodecBuffer outBuffer;
    ret = component_->UseBuffer(outputIndex, *omxBuffer.get(), outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ret = component_->FreeBuffer(outputIndex, outBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

// Use buffer on input index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_005, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_INPUT, param);

    auto err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);
    err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, 1, param.nBufferSize);
    ASSERT_FALSE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    ASSERT_TRUE(err);
}

// Use buffer on output index error when OMX_ErrorInsufficientResources
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseBufferAndFreeBufferTest_006, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_OUTPUT, param);

    auto err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);
    err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, 1, param.nBufferSize);
    ASSERT_FALSE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    ASSERT_TRUE(err);
}
#endif

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyAndFillBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_INPUT, param);
    auto err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    GetPortParameter(PortIndex::PORT_INDEX_OUTPUT, param);
    err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_EXECUTING);

    FillAndEmptyAllBuffer(CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);

    err = FreeBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    ASSERT_TRUE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    ASSERT_TRUE(err);
    WaitState(CODEC_STATE_LOADED);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyAndFillBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitBufferHandleParameter(param);
    GetPortParameter(PortIndex::PORT_INDEX_INPUT, param);
    auto err = UseDynaBuffer(PortIndex::PORT_INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    GetPortParameter(PortIndex::PORT_INDEX_OUTPUT, param);
    err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_EXECUTING);

    FillAndEmptyAllBuffer(CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);

    err = FreeBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    ASSERT_TRUE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    ASSERT_TRUE(err);
    WaitState(CODEC_STATE_LOADED);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyAndFillBufferTest_003, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    GetPortParameter(PortIndex::PORT_INDEX_INPUT, param);
    auto err = AllocateBufferOnPort(PortIndex::PORT_INDEX_INPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    GetPortParameter(PortIndex::PORT_INDEX_OUTPUT, param);
    err = AllocateBufferOnPort(PortIndex::PORT_INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_EXECUTING);

    FillAndEmptyAllBuffer(CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);
    ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    WaitState(CODEC_STATE_IDLE);

    err = FreeBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    ASSERT_TRUE(err);
    err = FreeBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    ASSERT_TRUE(err);
    WaitState(CODEC_STATE_LOADED);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiUseEglImageTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    auto eglImage = std::make_unique<int8_t[]>(BUFFER_SIZE);
    ASSERT_TRUE(eglImage != nullptr);
    std::vector<int8_t> eglImageVec;
    eglImageVec.assign(eglImage.get(), eglImage.get() + BUFFER_SIZE);
    struct OmxCodecBuffer outbuffer;
    int32_t ret = component_->UseEglImage(inputIndex, omxBuffer, outbuffer, eglImageVec);
    ASSERT_NE(ret, HDF_SUCCESS);
    eglImage = nullptr;
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFillThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = component_->FillThisBuffer(omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiEmptyThisBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = component_->EmptyThisBuffer(omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetCallbackTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    callback_ = new CodecCallbackService();
    ASSERT_TRUE(callback_ != nullptr);
    auto ret = component_->SetCallbacks(callback_, APP_DATA);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiSetCallbackTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    auto ret = component_->SetCallbacks(nullptr, APP_DATA);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiRoleEnumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<uint8_t> role;
    auto ret = component_->ComponentRoleEnum(role, 0);
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

HWTEST_F(CodecHdiOmxTest, HdfCodecHdiRoleEnumTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<uint8_t> role;
    auto ret = component_->ComponentRoleEnum(role, MAX_ROLE_INDEX);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Release input buffer
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = component_->FreeBuffer(outputIndex, omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// Release input buffer
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiFreeBufferTest_002, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    struct OmxCodecBuffer omxBuffer;
    InitOmxCodecBuffer(omxBuffer, CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer.bufferId = BUFFER_ID_ERROR;
    auto ret = component_->FreeBuffer(inputIndex, omxBuffer);
    ASSERT_NE(ret, HDF_SUCCESS);
}

#ifdef SUPPORT_OMX_EXTEND
// When ComponentDeInit, must change to Loaded State
HWTEST_F(CodecHdiOmxTest, HdfCodecHdiDeInitTest_001, TestSize.Level1)
{
    ASSERT_TRUE(component_ != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = component_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    // State changed OMX_StateIdle when release all this buffer
    WaitState(CODEC_STATE_LOADED);
    ret = component_->ComponentDeInit();
    ASSERT_EQ(ret, HDF_SUCCESS);
}
#endif

}  // namespace
