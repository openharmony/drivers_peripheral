/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_hdi_encode.h"
#include <hdf_base.h>
#include <unistd.h>
#include "codec_component_manager.h"
#include "codec_omx_ext.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
#define HDF_LOG_TAG codec_omx_hdi_enc
IDisplayBuffer *CodecHdiEncode::buffer_ = nullptr;

namespace {
    constexpr int32_t FRAME = 30 << 16;
    constexpr int32_t BUFFER_COUNT = 10;
    constexpr int32_t BITRATE = 3000000;
    constexpr int32_t FD_SIZE = sizeof(int);
    constexpr uint32_t MAX_WAIT_COUNT = 3;
}

#define AV_COLOR_FORMAT (OMX_COLOR_FORMATTYPE) CODEC_COLOR_FORMAT_RGBA8888

static CodecHdiEncode *g_core = nullptr;
CodecHdiEncode::CodecHdiEncode()
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    useBufferHandle_ = false;
    width_ = 0;
    height_ = 0;
    count_ = 0;
    componentId_ = 0;
    color_ = ColorFormat::YUV420SP;
    codecMime_ = CodecMime::AVC;
    omxColorFormat_ = OMX_COLOR_FormatYUV420SemiPlanar;
}

CodecHdiEncode::~CodecHdiEncode()
{
    if (ioOut_.is_open()) {
        ioOut_.close();
    }
    if (ioIn_.is_open()) {
        ioIn_.close();
    }
}

void CodecHdiEncode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiEncode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

bool CodecHdiEncode::ReadOneFrame(char *buf, uint32_t &filledCount)
{
    bool ret = false;
    filledCount = ioIn_.read(buf, GetInputBufferSize()).gcount();
    if (ioIn_.eof()) {
        ret = true;
    }
    return ret;
}

bool CodecHdiEncode::Init(CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->stride_ = AlignUp(width_);
    this->useBufferHandle_ = opt.useBuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d]", width_, height_);
    // gralloc init
    codecMime_ = opt.codec;

    buffer_ = IDisplayBuffer::Get();
    color_ = opt.colorForamt;
    if (color_ == ColorFormat::RGBA8888) {
        omxColorFormat_ = AV_COLOR_FORMAT;
    } else if (color_ == ColorFormat::BGRA8888) {
        omxColorFormat_ = OMX_COLOR_Format32bitBGRA8888;
    }
    ioIn_.open(opt.fileInput, std::ios_base::binary);
    ioOut_.open(opt.fileOutput, std::ios_base::binary | std::ios_base::trunc);
    if (!ioOut_.is_open() || !ioIn_.is_open()) {
        HDF_LOGE("%{public}s:failed to open file %{public}s or %{public}s", __func__, opt.fileInput.c_str(),
                 opt.fileOutput.c_str());
        return false;
    }
    // Interface init
    omxMgr_ = GetCodecComponentManager();
    callback_ = CodecCallbackTypeGet(nullptr);
    if ((omxMgr_ == nullptr) || (callback_ == nullptr)) {
        HDF_LOGE("%{public}s:omxMgr_ or callback_ is null", __func__);
        return false;
    }
    // set the callback
    callback_->EventHandler = &CodecHdiEncode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiEncode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiEncode::OnFillBufferDone;

    // create a component
    auto err = GetComponent();
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }
    // get version
    struct CompVerInfo verInfo;
    (void)memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    err = client_->GetComponentVersion(client_, &verInfo);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }

    return true;
}

bool CodecHdiEncode::Configure()
{
    if (client_ == nullptr) {
        return false;
    }
    // set input width, height and COLOR, set output port width and height
    if (ConfigPortDefine() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigPortDefine error", __func__);
        return false;
    }
    if (ConfigBitMode() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigBitMode error", __func__);
        return false;
    }
    if (CheckAndUseBufferHandle() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigUseBufferHandle error", __func__);
        return false;
    }

    return true;
}

int32_t CodecHdiEncode::CheckAndUseBufferHandle()
{
    if (!useBufferHandle_) {
        return HDF_SUCCESS;
    }

    SupportBufferType param;
    InitParamInOhos(param);
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);

    auto err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, reinterpret_cast<int8_t *>(&param),
                                     sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:PORT_INDEX_OUTPUT, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    InitParamInOhos(param);
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, reinterpret_cast<int8_t *>(&param),
                                sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:PORT_INDEX_INPUT, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    GetBufferHandleUsageParams usage;
    InitParamInOhos(usage);
    usage.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    err = client_->GetParameter(client_, OMX_IndexParamGetBufferHandleUsage, reinterpret_cast<int8_t *>(&usage),
                                sizeof(usage));
    HDF_LOGI("OMX_GetParameter:GetBufferHandleUsage:PORT_INDEX_INPUT, err [%{public}x], usage[%{public}" PRIu64 "]",
             err, usage.usage);
    if (err != HDF_SUCCESS) {
        return err;
    }

    UseBufferType type;
    InitParamInOhos(type);
    type.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    type.bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
    err = client_->SetParameter(client_, OMX_IndexParamUseBufferType, reinterpret_cast<int8_t *>(&type), sizeof(type));
    HDF_LOGI("OMX_SetParameter:OMX_IndexParamUseBufferType:PORT_INDEX_INPUT, err [%{public}x]", err);
    return err;
}

bool CodecHdiEncode::UseBuffers()
{
    // command to IDLE
    auto err = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with OMX_CommandStateSet:OMX_StateIdle", __func__);
        return false;
    }

    // use buffer on input port
    err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort PORT_INDEX_INPUT error", __func__);
        return false;
    }

    // use buffer on output port
    err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort PORT_INDEX_OUTPUT error", __func__);
        return false;
    }

    if (useBufferHandle_ && CreateBufferHandle() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s CreateBufferHandle error", __func__);
        return false;
    }

    // wait executing state
    OMX_STATETYPE status;
    err = client_->GetState(client_, &status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState err [%{public}x]", __func__, err);
        return false;
    }

    // wait loaded
    if (status != OMX_StateIdle) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }
    return true;
}

int32_t CodecHdiEncode::UseBufferOnPort(PortIndex portIndex)
{
    int bufferSize = 0;
    int bufferCount = 0;
    bool portEnable = false;

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(portIndex);
    auto err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }
    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    {
        OMX_PARAM_BUFFERSUPPLIERTYPE param;
        InitParam(param);
        param.nPortIndex = static_cast<uint32_t>(portIndex);
        err = client_->GetParameter(client_, OMX_IndexParamCompBufferSupplier, reinterpret_cast<int8_t *>(&param),
                                    sizeof(param));
        HDF_LOGI("param.eBufferSupplier[%{public}d] err [%{public}d]", param.eBufferSupplier, err);
    }
    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        bufferSize = GetInputBufferSize();
    } else if (bufferSize == 0) {
        bufferSize = width_ * height_;
        HDF_LOGI("bufferSize[%{public}d], width[%{public}d], height[%{public}d]", bufferSize, width_, height_);
    }
    if (useBufferHandle_ && portIndex == PortIndex::PORT_INDEX_INPUT) {
        err = UseDynaBuffer(bufferCount, bufferSize);
    } else {
        err = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    }
    if (err != HDF_SUCCESS) {
        return err;
    }
    // if port is disable, changed to enable
    if (!portEnable) {
        err = client_->SendCommand(client_, OMX_CommandPortEnable, static_cast<uint32_t>(portIndex), NULL, 0);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s SendCommand OMX_CommandPortEnable::PORT_INDEX_INPUT error", __func__);
            return err;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        return HDF_ERR_INVALID_PARAM;
    }

    for (int i = 0; i < bufferCount; i++) {
        auto omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.s.nVersionMajor = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = AshmemCreate(0, bufferSize);
        shared_ptr<Ashmem> spSharedMem = make_shared<Ashmem>(fd, bufferSize);
        omxBuffer->bufferLen = FD_SIZE;
        omxBuffer->buffer = reinterpret_cast<uint8_t *>(fd);
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;
        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            omxBuffer->type = READ_ONLY_TYPE;
            spSharedMem->MapReadAndWriteAshmem();
        } else {
            omxBuffer->type = READ_WRITE_TYPE;
            spSharedMem->MapReadOnlyAshmem();
        }
        auto err = client_->UseBuffer(client_, static_cast<uint32_t>(portIndex), omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            spSharedMem->UnmapAshmem();
            spSharedMem->CloseAshmem();
            spSharedMem = nullptr;
            return err;
        }

        omxBuffer->bufferLen = 0;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

        auto bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->avSharedPtr = spSharedMem;
        bufferInfo->portIndex = portIndex;
        omxBuffers_.insert(std::make_pair(omxBuffer->bufferId, bufferInfo));
        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            unUsedInBuffers_.push_back(omxBuffer->bufferId);
        } else {
            unUsedOutBuffers_.push_back(omxBuffer->bufferId);
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::UseDynaBuffer(int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        return HDF_ERR_INVALID_PARAM;
    }

    for (int i = 0; i < bufferCount; i++) {
        auto omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.s.nVersionMajor = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
        omxBuffer->bufferLen = 0;
        omxBuffer->buffer = nullptr;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;

        auto err = client_->UseBuffer(client_, static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT), omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  PORT_INDEX_INPUT", __func__);
            return err;
        }

        omxBuffer->bufferLen = 0;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

        auto bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->portIndex = PortIndex::PORT_INDEX_INPUT;
        omxBuffers_.insert(std::make_pair(omxBuffer->bufferId, bufferInfo));
        unUsedInBuffers_.push_back(omxBuffer->bufferId);
    }
    return HDF_SUCCESS;
}

void CodecHdiEncode::FreeBuffers()
{
    // send command to loaded state
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateLoaded, nullptr, 0);

    // All the buffer must be released, otherwise the component will wait
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        (void)client_->FreeBuffer(client_, static_cast<uint32_t>(bufferInfo->portIndex), bufferInfo->omxBuffer.get());
        iter = omxBuffers_.erase(iter);
    }
    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    // wait loaded
    OMX_STATETYPE status = OMX_StateLoaded;
    int32_t tryCount = MAX_WAIT_COUNT;
    do {
        int32_t err = client_->GetState(client_, &status);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
            break;
        }
        if (status != OMX_StateLoaded) {
            HDF_LOGI("Wait for OMX_StateLoaded status");
            this->WaitForStatusChanged();
        }
        tryCount--;
    } while ((status != OMX_StateLoaded) && (tryCount > 0));
}

void CodecHdiEncode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    CodecComponentTypeRelease(client_);
    client_ = nullptr;
    CodecComponentManagerRelease();
}

bool CodecHdiEncode::FillAllTheBuffer()
{
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("fill bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter != omxBuffers_.end()) {
            auto bufferInfo = iter->second;
            auto err = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
            if (err != HDF_SUCCESS) {
                HDF_LOGE("%{public}s FillThisBuffer error", __func__);
                return false;
            }
        }
    }
    return true;
}

int CodecHdiEncode::GetFreeBufferId()
{
    int bufferID = -1;
    unique_lock<mutex> ulk(lockInputBuffers_);
    size_t nSize = this->unUsedInBuffers_.size();
    if (nSize > 0) {
        bufferID = unUsedInBuffers_.front();
        unUsedInBuffers_.pop_front();
    }
    return bufferID;
}

void CodecHdiEncode::Run()
{
    auto err = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateExecuting, NULL, 0);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with OMX_CommandStateSet:OMX_StateIdle", __func__);
        return;
    }
    auto t1 = std::chrono::system_clock::now();
    if (!FillAllTheBuffer()) {
        HDF_LOGE("%{public}s FillAllTheBuffer error", __func__);
        return;
    }
    bool endFlag = false;
    while (!endFlag) {
        int bufferID = GetFreeBufferId();
        if (this->exit_) {
            break;
        }
        if (bufferID < 0) {
            usleep(10000);  // 10000: sleep time 10ms
            continue;
        }
        auto iter = omxBuffers_.find(bufferID);
        if (iter == omxBuffers_.end()) {
            continue;
        }
        auto bufferInfo = iter->second;
        if (!FillCodecBuffer(bufferInfo, endFlag)) {
            break;
        }
        err = client_->EmptyThisBuffer(client_, bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    while (!this->exit_) {
        usleep(10000);  // 10000: sleep time 10ms
    }
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    auto t2 = std::chrono::system_clock::now();
    std::chrono::duration<double> diff = t2 - t1;
    HDF_LOGI("encoder costtime %{public}f, count=%{public}d", diff.count(), count_);
    return;
}

bool CodecHdiEncode::FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &endFlag)
{
    if (buffer_ == nullptr) {
        HDF_LOGE("%{public}s buffer_ is null", __func__);
        return false;
    }
    if (useBufferHandle_) {
        int bufferHandleId = freeBufferHandles_.front();
        if (bufferHandleId < 0 || bufferHandleId >= BUFFER_COUNT) {
            HDF_LOGE("%{public}s bufferHandleId [%{public}d]", __func__, bufferHandleId);
            return false;
        }
        freeBufferHandles_.pop_front();
        bufferInfo->bufferHandleId = bufferHandleId;
        BufferHandle *bufferHandle = bufferHandles_[bufferHandleId];
        if (bufferHandle != nullptr) {
            buffer_->Mmap(*bufferHandle);
            endFlag =
                this->ReadOneFrame(reinterpret_cast<char *>(bufferHandle->virAddr), bufferInfo->omxBuffer->filledLen);
            bufferInfo->omxBuffer->filledLen = bufferHandle->stride * bufferHandle->height;
            buffer_->Unmap(*bufferHandle);
            bufferInfo->omxBuffer->buffer = reinterpret_cast<uint8_t *>(bufferHandle);
            bufferInfo->omxBuffer->bufferLen =
                sizeof(BufferHandle) + sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts);
        }
    } else {
        // read data from ashmem
        void *sharedAddr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(0, 0));
        endFlag = this->ReadOneFrame(reinterpret_cast<char *>(sharedAddr), bufferInfo->omxBuffer->filledLen);
    }
    bufferInfo->omxBuffer->offset = 0;
    if (endFlag) {
        bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
    }

    return true;
}

int32_t CodecHdiEncode::CreateBufferHandle()
{
    if (buffer_ == nullptr) {
        HDF_LOGE("%{public}s buffer_ is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    PixelFormat pixForamt = PIXEL_FMT_YCBCR_420_SP;
    if (color_ == ColorFormat::RGBA8888) {
        pixForamt = PIXEL_FMT_RGBA_8888;
    } else if (color_ == ColorFormat::BGRA8888) {
        pixForamt = PIXEL_FMT_BGRA_8888;
    }

    AllocInfo alloc = {.width = this->stride_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = pixForamt};

    int32_t err = HDF_SUCCESS;
    for (size_t i = 0; i < BUFFER_COUNT; i++) {
        BufferHandle *bufferHandle = nullptr;
        err = buffer_->AllocMem(alloc, bufferHandle);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s AllocMem fail", __func__);
            return err;
        }
        bufferHandles_.emplace(std::make_pair(i, bufferHandle));
        freeBufferHandles_.push_back(i);
    }
    return err;
}

int32_t CodecHdiEncode::OnEvent(struct CodecCallbackType *self, enum OMX_EVENTTYPE event, struct EventInfo *info)
{
    HDF_LOGI("OnEvent: pAppData[%{public} " PRId64 "], eEvent [%{public}d], nData1[%{public}d]", info->appData, event,
             info->data1);
    if (event == OMX_EventCmdComplete) {
        OMX_COMMANDTYPE cmd = static_cast<OMX_COMMANDTYPE>(info->data1);
        if (OMX_CommandStateSet == cmd) {
            HDF_LOGI("OMX_CommandStateSet reached");
            g_core->OnStatusChanged();
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::OnEmptyBufferDone(struct CodecCallbackType *self, int64_t appData,
                                          const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("OnEmptyBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiEncode::OnFillBufferDone(struct CodecCallbackType *self, int64_t appData,
                                         const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("OnFillBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnFillBufferDone(*buffer);
}

uint32_t CodecHdiEncode::GetInputBufferSize()
{
    if (color_ == ColorFormat::YUV420SP) {
        return (width_ * height_ * 3 / 2);  // 3:byte alignment, 2:byte alignment
    } else {
        return (width_ * height_ * 4);  // 4: byte alignment for RGBA or BGRA
    }
}

int32_t CodecHdiEncode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    if (useBufferHandle_) {
        auto bufferInfo = omxBuffers_[buffer.bufferId];
        freeBufferHandles_.push_back(bufferInfo->bufferHandleId);
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::OnFillBufferDone(const struct OmxCodecBuffer &buffer)
{
    if (exit_) {
        return HDF_SUCCESS;
    }

    auto iter = omxBuffers_.find(buffer.bufferId);
    if (iter == omxBuffers_.end() || !iter->second) {
        return HDF_SUCCESS;
    }

    auto bufferInfo = iter->second;
    void *addr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset));
    // save to file
    ioOut_.write(static_cast<char *>(addr), buffer.filledLen);
    ioOut_.flush();
    count_++;
    if ((buffer.flag & static_cast<uint32_t>(OMX_BUFFERFLAG_EOS)) != 0) {
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }
    auto err = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
    if (err != HDF_SUCCESS) {
        HDF_LOGE("FillThisBuffer error");
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::ConfigPortDefine()
{
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    auto err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    HDF_LOGI("PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;

    param.format.video.eColorFormat = omxColorFormat_;
    err =
        client_->SetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }

    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    HDF_LOGI("PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    err =
        client_->SetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    return HDF_SUCCESS;
}
int32_t CodecHdiEncode::GetComponent()
{
    int32_t count = omxMgr_->GetComponentNum();
    if (count <= 0) {
        HDF_LOGE("%{public}s: GetComponentNum ret %{public}d", __func__, count);
        return HDF_FAILURE;
    }
    auto caps = std::make_unique<CodecCompCapability[]>(count);
    auto err = omxMgr_->GetComponentCapabilityList(caps.get(), count);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetComponentCapabilityList ret %{public}d", __func__, err);
        return err;
    }
    std::string compName("");
    for (int32_t i = 0; i < count; i++) {
        if (caps[i].type != VIDEO_ENCODER) {
            continue;
        }
        if (((caps[i].role == MEDIA_ROLETYPE_VIDEO_AVC) && (codecMime_ == CodecMime::AVC)) ||
            ((caps[i].role == MEDIA_ROLETYPE_VIDEO_HEVC) && (codecMime_ == CodecMime::HEVC))) {
            compName = caps[i].compName;
            break;
        }
    }
    if (compName.empty()) {
        HDF_LOGE("%{public}s: role is unexpected ", __func__);
        return HDF_FAILURE;
    }
    return omxMgr_->CreateComponent(&client_, &componentId_, compName.data(), reinterpret_cast<int64_t>(this),
                                    callback_);
}

OMX_VIDEO_CODINGTYPE CodecHdiEncode::GetCompressFormat()
{
    OMX_VIDEO_CODINGTYPE compressFmt = OMX_VIDEO_CodingAVC;
    switch (codecMime_) {
        case CodecMime::AVC:
            compressFmt = OMX_VIDEO_CodingAVC;
            break;
        case CodecMime::HEVC:
            compressFmt = (OMX_VIDEO_CODINGTYPE)CODEC_OMX_VIDEO_CodingHEVC;
            break;
        case CodecMime::MPEG4:
            compressFmt = OMX_VIDEO_CodingMPEG4;
            break;
        case CodecMime::VP9:
            compressFmt = (OMX_VIDEO_CODINGTYPE)CODEC_OMX_VIDEO_CodingVP9;
            break;
        default:
            break;
    }
    return compressFmt;
}
int32_t CodecHdiEncode::ConfigBitMode()
{
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    auto err = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                     sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat");
        return err;
    }
    HDF_LOGI("set Format PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;
    param.eCompressionFormat = GetCompressFormat();
    err = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }

    OMX_VIDEO_PARAM_BITRATETYPE biteType;
    InitParam(biteType);
    biteType.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    err = client_->GetParameter(client_, OMX_IndexParamVideoBitrate, reinterpret_cast<int8_t *>(&biteType),
                                sizeof(biteType));
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s OMX_GetParameter portindex = PORT_INDEX_OUTPUT, err[%{public}d]", __func__, err);
        return err;
    }
    HDF_LOGI("get PORT_INDEX_OUTPUT:OMX_IndexParamVideoBitrate, bit_mode[%{public}d], biterate:[%{publicd}d]",
             biteType.eControlRate, biteType.nTargetBitrate);

    biteType.eControlRate = OMX_Video_ControlRateConstant;
    biteType.nTargetBitrate = BITRATE;
    err = client_->SetParameter(client_, OMX_IndexParamVideoBitrate, reinterpret_cast<int8_t *>(&biteType),
                                sizeof(biteType));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }
    return HDF_SUCCESS;
}

int main(int argc, char *argv[])
{
    CommandOpt opt;
    CommandParse parse;
    if (!parse.Parse(argc, argv, opt)) {
        return 0;
    }

    if (g_core == nullptr) {
        g_core = new CodecHdiEncode();
    }

    if (!g_core->Init(opt)) {
        delete g_core;
        g_core = nullptr;
        return HDF_FAILURE;
    }

    if (!g_core->Configure()) {
        delete g_core;
        g_core = nullptr;
        return HDF_FAILURE;
    }

    if (!g_core->UseBuffers()) {
        delete g_core;
        g_core = nullptr;
        return HDF_FAILURE;
    }

    g_core->Run();

    g_core->FreeBuffers();

    g_core->Release();
    delete g_core;
    g_core = nullptr;
}