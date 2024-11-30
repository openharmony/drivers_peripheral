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

#include <cstdio>
#include <unistd.h>
#include "codec_function_utils.h"
#include <gtest/gtest.h>
#include <securec.h>
#include <servmgr_hdi.h>

#define HDF_LOG_TAG codec_hdi_test

using namespace std;
using namespace OHOS::HDI::Codec::V3_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
IDisplayBuffer *FunctionUtil::buffer_ = nullptr;

FunctionUtil::FunctionUtil(CodecVersionType version)
{
    buffer_ = IDisplayBuffer::Get();
    version_ = version;
}

FunctionUtil::~FunctionUtil()
{
    buffer_ = nullptr;
}

uint32_t FunctionUtil::AlignUp(uint32_t width)
{
    return (((width) + ALIGNMENT - 1) & (~(ALIGNMENT - 1)));
}

void FunctionUtil::InitOmxCodecBuffer(OmxCodecBuffer &buffer, CodecBufferType type)
{
    buffer.bufferType = type;
    buffer.fenceFd = ERROE_FENCEFD;
    buffer.version = version_;
    buffer.allocLen = BUFFER_SIZE;
    buffer.fd = FD_DEFAULT;
    buffer.bufferhandle = nullptr;
    buffer.pts = 0;
    buffer.flag = 0;
    buffer.size = sizeof(OmxCodecBuffer);
    buffer.type = READ_ONLY_TYPE;
}

void FunctionUtil::InitCodecBufferWithAshMem(enum PortIndex port, int bufferSize, shared_ptr<OmxCodecBuffer> omxBuffer,
    shared_ptr<OHOS::Ashmem> sharedMem)
{
    InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
    omxBuffer->fd = sharedMem->GetAshmemFd();
    omxBuffer->allocLen = bufferSize;
    if (port == PortIndex::INDEX_INPUT) {
        omxBuffer->type = READ_ONLY_TYPE;
        sharedMem->MapReadAndWriteAshmem();
    } else {
        omxBuffer->type = READ_WRITE_TYPE;
        sharedMem->MapReadOnlyAshmem();
    }
}

bool FunctionUtil::InitBufferHandleParameter(sptr<ICodecComponent> component, OMX_PARAM_PORTDEFINITIONTYPE &param,
    uint32_t port, CodecBufferType bufferType)
{
    InitParam(param);
    param.nPortIndex = port;
    std::vector<int8_t> inParam, outParam;
    ObjectToVector(param, inParam);
    auto ret = component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GetParameter OMX_IndexParamPortDefinition error");
        return false;
    }

    VectorToObject(outParam, param);
    param.format.video.nFrameWidth = WIDTH;
    param.format.video.nFrameHeight = HEIGHT;
    param.format.video.nStride = AlignUp(WIDTH);
    param.format.video.nSliceHeight = HEIGHT;
    param.format.video.eColorFormat = OMX_COLOR_FormatYUV420SemiPlanar;
    std::vector<int8_t> enc;
    ObjectToVector(param, enc);
    ret = component->SetParameter(OMX_IndexParamPortDefinition, enc);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("SetParameter OMX_IndexParamPortDefinition error");
        return false;
    }

    std::vector<int8_t> data;
    UseBufferType type;
    type.size = sizeof(UseBufferType);
    type.version.s.nVersionMajor = 1;
    type.portIndex = port;
    type.bufferType = bufferType;
    ObjectToVector(type, data);
    ret = component->SetParameter(OMX_IndexParamUseBufferType, data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("SetParameter OMX_IndexParamUseBufferType error");
        return false;
    }
    return true;
}

bool FunctionUtil::FillCodecBufferWithBufferHandle(shared_ptr<OmxCodecBuffer> omxBuffer)
{
    AllocInfo alloc = {.width = WIDTH,
                       .height = HEIGHT,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};

    BufferHandle *bufferHandle = nullptr;
    if (buffer_ == nullptr) {
        HDF_LOGE("buffer_ is nullptr");
        return false;
    }
    auto ret = buffer_->AllocMem(alloc, bufferHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("AllocMem error");
        return false;
    }
    omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
    return true;
}

bool FunctionUtil::UseDynaBuffer(sptr<ICodecComponent> component, enum PortIndex port, int bufferCount,
    int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("bufferCount <= 0 or bufferSize <= 0");
        return false;
    }

    for (int i = 0; i < bufferCount; i++) {
        auto omxBuffer = std::make_shared<OmxCodecBuffer>();
        InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_DYNAMIC_HANDLE);
        FillCodecBufferWithBufferHandle(omxBuffer);
        omxBuffer->allocLen = WIDTH * HEIGHT * NUMERATOR / DENOMINATOR;

        OmxCodecBuffer outBuffer;
        auto ret = component->UseBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("UseBuffer error");
            return false;
        }

        omxBuffer->bufferId = outBuffer.bufferId;
        auto bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        inputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
    }
    return true;
}

bool FunctionUtil::UseHandleBuffer(sptr<ICodecComponent> component, enum PortIndex port,
    int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("bufferCount <= 0 or bufferSize <= 0");
        return false;
    }

    for (int i = 0; i < bufferCount; i++) {
        auto omxBuffer = std::make_shared<OmxCodecBuffer>();
        InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_HANDLE);
        FillCodecBufferWithBufferHandle(omxBuffer);
        omxBuffer->allocLen = WIDTH * HEIGHT * NUMERATOR / DENOMINATOR;

        OmxCodecBuffer outBuffer;
        int32_t ret = component->UseBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("UseBuffer error");
            return false;
        }

        omxBuffer->bufferId = outBuffer.bufferId;
        auto bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        outputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
    }
    return true;
}

bool FunctionUtil::UseBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port,
    int32_t bufferCount, int32_t bufferSize)
{
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        int fd = OHOS::AshmemCreate(0, bufferSize);
        shared_ptr<OHOS::Ashmem> sharedMem = make_shared<OHOS::Ashmem>(fd, bufferSize);
        InitCodecBufferWithAshMem(port, bufferSize, omxBuffer, sharedMem);
        OmxCodecBuffer outBuffer;
        int32_t err = component->UseBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("UseBuffer error");
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            return false;
        }

        omxBuffer->bufferId = outBuffer.bufferId;
        omxBuffer->fd = FD_DEFAULT;
        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->sharedMem = sharedMem;
        if (port == PortIndex::INDEX_INPUT) {
            inputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        } else {
            outputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        }
    }
    return true;
}

bool FunctionUtil::AllocateBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port,
    int32_t bufferCount, int32_t bufferSize)
{
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        InitOmxCodecBuffer(*omxBuffer.get(), CODEC_BUFFER_TYPE_AVSHARE_MEM_FD);
        omxBuffer->allocLen = bufferSize;
        if (port == PortIndex::INDEX_INPUT) {
            omxBuffer->type = READ_ONLY_TYPE;
        } else {
            omxBuffer->type = READ_WRITE_TYPE;
        }

        OmxCodecBuffer outBuffer;
        auto err = component->AllocateBuffer(static_cast<uint32_t>(port), *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("AllocateBuffer error");
            return false;
        }
        omxBuffer->type = outBuffer.type;
        omxBuffer->bufferId = outBuffer.bufferId;

        int fd = outBuffer.fd;
        shared_ptr<OHOS::Ashmem> sharedMem = make_shared<OHOS::Ashmem>(fd, bufferSize);

        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->sharedMem = sharedMem;
        if (port == PortIndex::INDEX_INPUT) {
            sharedMem->MapReadAndWriteAshmem();
            inputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        } else {
            sharedMem->MapReadOnlyAshmem();
            outputBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        }
    }
    return true;
}

bool FunctionUtil::FreeBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port)
{
    int32_t ret;
    std::map<int32_t, std::shared_ptr<BufferInfo>> &buffer = inputBuffers_;
    if (port == PortIndex::INDEX_OUTPUT) {
        buffer = outputBuffers_;
    }
    for (auto [bufferId, bufferInfo] : buffer) {
        ret = component->FreeBuffer(static_cast<uint32_t>(port), *bufferInfo->omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("FreeBuffer error");
            return false;
        }
    }
    buffer.clear();
    return true;
}

int32_t FunctionUtil::GetPortParameter(sptr<ICodecComponent> component, PortIndex index,
    OMX_PARAM_PORTDEFINITIONTYPE &param)
{
    InitParam(param);
    param.nPortIndex = static_cast<OMX_U32>(index);
    std::vector<int8_t> inParam;
    ObjectToVector(param, inParam);

    std::vector<int8_t> outParam;
    auto ret = component->GetParameter(OMX_IndexParamPortDefinition, inParam, outParam);
    VectorToObject(outParam, param);
    return ret;
}

bool FunctionUtil::PushAlongParam(OmxCodecBuffer &omxBuffer)
{
    const std::string processName = "cast_engine_service";
    ProcessNameParam nameParam;
    this->InitExtParam(nameParam);
    int32_t ret = strcpy_s(nameParam.processName, sizeof(nameParam.processName), processName.c_str());
    if (ret != EOK) {
        return false;
    }

    uint32_t size = sizeof(nameParam);
    uint8_t *ptr = reinterpret_cast<uint8_t*>(&nameParam);
    for (uint32_t i = 0; i < size; i++) {
        omxBuffer.alongParam.push_back(*(ptr + i));
    }

    constexpr uint32_t QP_RANGE_MIN = 12;
    constexpr uint32_t QP_RANGE_MAX = 43;
    CodecQPRangeParam param;
    this->InitExtParam(param);
    param.minQp = QP_RANGE_MIN;
    param.maxQp = QP_RANGE_MAX;
    size = sizeof(param);
    ptr = reinterpret_cast<uint8_t*>(&param);
    for (uint32_t i = 0; i < size; i++) {
        omxBuffer.alongParam.push_back(*(ptr + i));
    }
    return true;
}

bool FunctionUtil::FillAndEmptyAllBuffer(sptr<ICodecComponent> component, CodecBufferType type)
{
    int32_t ret;
    auto iter = outputBuffers_.begin();
    for (; iter != outputBuffers_.end(); iter++) {
        auto bufferInfo = iter->second;
        if (type != bufferInfo->omxBuffer->bufferType) {
            continue;
        }
        ret = component->FillThisBuffer(*bufferInfo->omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("FillThisBuffer error");
            return false;
        }
    }
    iter = inputBuffers_.begin();
    for (; iter != inputBuffers_.end(); iter++) {
        auto bufferInfo = iter->second;
        if (type != bufferInfo->omxBuffer->bufferType) {
            continue;
        }
        if (type == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE && (!PushAlongParam(*bufferInfo->omxBuffer.get()))) {
            HDF_LOGE("PushAlongParam error");
            return false;
        }
        ret = component->EmptyThisBuffer(*bufferInfo->omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("EmptyThisBuffer error");
            return false;
        }
    }
    return true;
}

bool FunctionUtil::WaitState(sptr<ICodecComponent> component, CodecStateType objState)
{
    CodecStateType state = CODEC_STATE_INVALID;
    uint32_t count = 0;
    do {
        usleep(WAIT_TIME);
        auto ret = component->GetState(state);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("EmptyThisBuffer error");
            return false;
        }
        count++;
    } while (state != objState && count <= MAX_WAIT);
    return true;
}

