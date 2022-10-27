/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "codec_hdi_adapter_encode.h"
#include <dlfcn.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>
#include <chrono>
#include <sys/stat.h>
#include "codec_type.h"
#include "codec_omx_ext.h"

using namespace std;
using namespace OHOS;

#define HDF_LOG_TAG codec_omx_hdi_enc
OHOS::HDI::Display::V1_0::IDisplayGralloc *CodecHdiAdapterEncode::gralloc_ = nullptr;
namespace {
    constexpr int16_t BPS_BASE = 16;
    constexpr int16_t BPS_MAX = 17;
    constexpr int16_t BPS_MEDIUM = 15;
    constexpr int16_t BPS_MIN = 1;
    constexpr int16_t BPS_TARGET = 2;
    constexpr int16_t FIXQP_INIT_VALUE = 20;
    constexpr int16_t FIXQP_MAX_VALUE = 20;
    constexpr int16_t FIXQP_MIN_VALUE = 20;
    constexpr int16_t FIXQP_MAX_I_VALUE = 20;
    constexpr int16_t FIXQP_MIN_I_VALUE = 20;
    constexpr int16_t FIXQP_IP_VALUE = 2;
    constexpr int16_t OTHER_QP_INIT_VALUE = 26;
    constexpr int16_t OTHER_QP_MAX_VALUE = 51;
    constexpr int16_t OTHER_QP_MIN_VALUE = 10;
    constexpr int16_t OTHER_QP_MAX_I_VALUE = 51;
    constexpr int16_t OTHER_QP_MIN_I_VALUE = 10;
    constexpr int16_t OTHER_QP_IP_VALUE = 2;
    constexpr int16_t AVC_SETUP_LEVEL_DEFAULT = 40;
    constexpr int16_t AVC_SETUP_CABAC_EN_DEFAULT = 1;
    constexpr int16_t AVC_SETUP_CABAC_IDC_DEFAULT = 0;
    constexpr int16_t AVC_SETUP_TRANS_DEFAULT = 1;
    constexpr int16_t AVC_SETUP_PROFILE_DEFAULT = 100;
    constexpr int16_t ENC_SETUP_FPS_IN_NUM = 24;
    constexpr int16_t ENC_SETUP_FPS_OUT_NUM = 24;
    constexpr int32_t FRAME = (30 << 16);
    constexpr int32_t BUFFER_COUNT = 10;
    constexpr int32_t FD_SIZE = sizeof(int);
    constexpr int32_t USLEEP_TIME = 10000;
    constexpr const char *ENCODER_AVC = "rk.video_encoder.avc";
    constexpr int32_t DENOMINATOR = 2;
    constexpr int32_t NUMERATOR = 3;
}

#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar

static CodecHdiAdapterEncode *g_core = nullptr;

CodecHdiAdapterEncode::CodecHdiAdapterEncode() : fpIn_(nullptr), fpOut_(nullptr)
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    useBufferHandle_ = false;
    width_ = 0;
    height_ = 0;
    componentId_ = 0;
    srcFileSize_ = 0;
    totalSrcSize_ = 0;
}

CodecHdiAdapterEncode::~CodecHdiAdapterEncode()
{
    if (fpOut_ != nullptr) {
        fclose(fpOut_);
        fpOut_ = nullptr;
    }
    if (fpIn_ != nullptr) {
        fclose(fpIn_);
        fpIn_ = nullptr;
    }
}

void CodecHdiAdapterEncode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiAdapterEncode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

bool CodecHdiAdapterEncode::ReadOneFrame(FILE *fp, char *buf, uint32_t &filledCount)
{
    bool ret = false;
    filledCount = fread(buf, 1, width_ * height_ * NUMERATOR / DENOMINATOR, fp);
    totalSrcSize_ += filledCount;
    if (totalSrcSize_ >= srcFileSize_) {
        ret = true;
    }
    return ret;
}

bool CodecHdiAdapterEncode::Init(CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->stride_ = AlignUp(width_);
    this->useBufferHandle_ = opt.useBuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d],stride_[%{public}d]", width_, height_, stride_);
    // gralloc init
    gralloc_ = OHOS::HDI::Display::V1_0::IDisplayGralloc::Get();
    
    struct stat fileStat = {0};
    stat(opt.fileInput.c_str(), &fileStat);
    srcFileSize_ = fileStat.st_size;

    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
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
    callback_->EventHandler = &CodecHdiAdapterEncode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiAdapterEncode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiAdapterEncode::OnFillBufferDone;

    // create a component
    auto ret =
        omxMgr_->CreateComponent(&client_, &componentId_, const_cast<char *>(ENCODER_AVC), (int64_t)this, callback_);
    if (ret != HDF_SUCCESS || client_ == nullptr) {
        HDF_LOGE("%{public}s errNo[%{public}d] CreateComponent or client is null", __func__, ret);
        return false;
    }

    return true;
}

bool CodecHdiAdapterEncode::Configure()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s component is null", __func__);
        return false;
    }
    // set input width, height and COLOR, set ouput port width and height
    if (ConfigPortDefine() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigPortDefine error", __func__);
        return false;
    }

    if (ConfigBitMode() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigBitMode error", __func__);
        return false;
    }
    if (ConfigMppPassthrough() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigMppPassthrough error", __func__);
        return false;
    }

    return true;
}

bool CodecHdiAdapterEncode::UseBuffers()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    // commad to IDLE
    auto ret = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] SendCommand with StateSet:OMX_StateIdle", __func__, ret);
        return false;
    }

    // use buffer on input port
    ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] UseBufferOnPort PORT_INDEX_INPUT", __func__, ret);
        return false;
    }

    // use buffer on output port
    ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] UseBufferOnPort PORT_INDEX_OUTPUT", __func__, ret);
        return false;
    }

    if (useBufferHandle_ && CreateBufferHandle() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s CreateBufferHandle error", __func__);
        return false;
    }

    // wait executing state
    enum OMX_STATETYPE status;
    ret = client_->GetState(client_, &status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState ret [%{public}x]", __func__, ret);
        return false;
    }

    // wait loaded
    if (status != OMX_StateIdle) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI("status is %{public}d", status);
    }
    return true;
}

int32_t CodecHdiAdapterEncode::UseBufferOnPort(PortIndex portIndex)
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    int32_t bufferSize = 0;
    int32_t bufferCount = 0;
    bool portEnable = false;

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)portIndex;
    auto ret = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, ret, portIndex);
        return ret;
    }

    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;

    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        bufferSize = width_ * height_ * DENOMINATOR;
    } else if (bufferSize == 0) {
        bufferSize = width_ * height_;
    }
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], buffer count [%{public}d], "
             "portEnable[%{public}d], ret [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, ret);
    if (useBufferHandle_ && portIndex == PortIndex::PORT_INDEX_INPUT) {
        ret = UseDynaBuffer(bufferCount, bufferSize);
    } else {
        ret = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d]UseDynaBuffer or UseBufferOnPort failed", __func__, ret);
    }

    return ret;
}

int32_t CodecHdiAdapterEncode::UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (client_ == nullptr || bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("%{public}s client is null or bufferCount or bufferSize <= 0", __func__);
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
        omxBuffer->buffer = reinterpret_cast<uint8_t *>((unsigned long)fd);
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
        auto ret = client_->UseBuffer(client_, (uint32_t)portIndex, omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s errNo[%{public}d] UseBuffer with portIndex[%{public}d]", __func__, ret, portIndex);
            spSharedMem->UnmapAshmem();
            spSharedMem->CloseAshmem();
            spSharedMem = nullptr;
            return ret;
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

int32_t CodecHdiAdapterEncode::UseDynaBuffer(int bufferCount, int bufferSize)
{
    if (client_ == nullptr || bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("%{public}s client is null or bufferCount or bufferSize <= 0", __func__);
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

        auto ret = client_->UseBuffer(client_, (uint32_t)PortIndex::PORT_INDEX_INPUT, omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s errNo[%{public}d] UseBuffer with PORT_INDEX_INPUT", __func__, ret);
            return ret;
        }

        omxBuffer->bufferLen = 0;
        auto bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->portIndex = PortIndex::PORT_INDEX_INPUT;
        omxBuffers_.insert(std::make_pair(omxBuffer->bufferId, bufferInfo));
        unUsedInBuffers_.push_back(omxBuffer->bufferId);
    }
    return HDF_SUCCESS;
}

void CodecHdiAdapterEncode::FreeBuffers()
{
    // send command to loaded state
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateLoaded, nullptr, 0);

    // All the buffer must be released, otherwise the component will wait
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        (void)client_->FreeBuffer(client_, (uint32_t)bufferInfo->portIndex, bufferInfo->omxBuffer.get());
        iter = omxBuffers_.erase(iter);
    }
    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    enum OMX_STATETYPE status;
    auto ret = client_->GetState(client_, &status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState error [%{public}x]", __func__, ret);
        return;
    }

    // wait
    if (status != OMX_StateLoaded) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI("status is %{public}d", status);
    }
}

void CodecHdiAdapterEncode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    client_ = nullptr;
    CodecComponentManagerRelease();
}

bool CodecHdiAdapterEncode::FillAllTheBuffer()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return false;
    }
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("fill bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter != omxBuffers_.end()) {
            auto bufferInfo = iter->second;
            auto ret = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%{public}s errNo[%{public}d] FillThisBuffer error", __func__, ret);
                return false;
            }
        }
    }
    return true;
}

int CodecHdiAdapterEncode::GetFreeBufferId()
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

void CodecHdiAdapterEncode::Run()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return;
    }
    auto ret = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateExecuting, NULL, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] SendCommand with StateSet:OMX_StateExecuting", __func__, ret);
        return;
    }
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
            usleep(USLEEP_TIME);
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

        ret = client_->EmptyThisBuffer(client_, bufferInfo->omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s errNo[%{public}d] EmptyThisBuffer error", __func__, ret);
            return;
        }
    }
    while (!this->exit_) {
        usleep(USLEEP_TIME);
    }
    ret = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] SendCommand with StateSet:OMX_StateIdle", __func__, ret);
        return;
    }
    return;
}

bool CodecHdiAdapterEncode::FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &endFlag)
{
    if (gralloc_ == nullptr) {
        HDF_LOGE("%{public}s gralloc_ is null", __func__);
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
            gralloc_->Mmap(*bufferHandle);
            endFlag = this->ReadOneFrame(fpIn_, reinterpret_cast<char *>(bufferHandle->virAddr),
                bufferInfo->omxBuffer->filledLen);
            bufferInfo->omxBuffer->filledLen = bufferHandle->stride * bufferHandle->height;
            gralloc_->Unmap(*bufferHandle);
            bufferInfo->omxBuffer->buffer = reinterpret_cast<uint8_t *>(bufferHandle);
            bufferInfo->omxBuffer->bufferLen =
                sizeof(BufferHandle) + sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts);
        }
    } else {
        // read data from ashmem
        void *sharedAddr = (void *)bufferInfo->avSharedPtr->ReadFromAshmem(0, 0);
        endFlag = this->ReadOneFrame(fpIn_, reinterpret_cast<char *>(sharedAddr), bufferInfo->omxBuffer->filledLen);
    }
    bufferInfo->omxBuffer->offset = 0;
    if (endFlag) {
        bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
    }

    return true;
}

int32_t CodecHdiAdapterEncode::CreateBufferHandle()
{
    if (gralloc_ == nullptr) {
        HDF_LOGE("%{public}s gralloc_ is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    AllocInfo alloc = {.width = this->stride_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};

    int32_t ret = HDF_SUCCESS;
    for (size_t i = 0; i < BUFFER_COUNT; i++) {
        BufferHandle *bufferHandle = nullptr;
        ret = gralloc_->AllocMem(alloc, bufferHandle);
        if (ret != HDF_SUCCESS) {
            FreeBufferHandle();
            HDF_LOGE("%{public}s errNo[%{public}d] AllocMem fail", __func__, ret);
            return ret;
        }
        bufferHandles_.emplace(std::make_pair(i, bufferHandle));
        freeBufferHandles_.push_back(i);
    }
    return ret;
}

void CodecHdiAdapterEncode::FreeBufferHandle()
{
    auto iter = bufferHandles_.begin();
    while (iter != bufferHandles_.end()) {
        auto bufferHandle = iter->second;
        gralloc_->FreeMem(*bufferHandle);
        iter = bufferHandles_.erase(iter);
    }
    freeBufferHandles_.clear();
}

int32_t CodecHdiAdapterEncode::OnEvent(struct CodecCallbackType *self, OMX_EVENTTYPE event, struct EventInfo *info)
{
    switch (event) {
        case OMX_EventCmdComplete: {
            OMX_COMMANDTYPE cmd = (OMX_COMMANDTYPE)info->data1;
            if (OMX_CommandStateSet == cmd) {
                HDF_LOGI("OMX_CommandStateSet reached");
                g_core->OnStatusChanged();
            }
            break;
        }

        default:
            break;
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiAdapterEncode::OnEmptyBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiAdapterEncode::OnFillBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    return g_core->OnFillBufferDone(*buffer);
}

int32_t CodecHdiAdapterEncode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    if (useBufferHandle_) {
        auto bufferInfo = omxBuffers_[buffer.bufferId];
        freeBufferHandles_.push_back(bufferInfo->bufferHandleId);
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiAdapterEncode::OnFillBufferDone(const struct OmxCodecBuffer &buffer)
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    if (exit_) {
        return HDF_SUCCESS;
    }

    auto iter = omxBuffers_.find(buffer.bufferId);
    if (iter == omxBuffers_.end() || !iter->second) {
        return HDF_SUCCESS;
    }

    auto bufferInfo = iter->second;
    const void *addr = bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset);
    (void)fwrite(addr, 1, buffer.filledLen, fpOut_);
    (void)fflush(fpOut_);
    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }

    auto ret = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] FillThisBuffer error", __func__, ret);
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

void CodecHdiAdapterEncode::CalcBpsRange(RKHdiRcSetup *rateControl, int32_t codecType)
{
    switch (rateControl->rcMode) {
        case MPP_ENC_RC_MODE_FIXQP: {
            /* do not setup bitrate on FIXQP mode */
            break;
        }
        case MPP_ENC_RC_MODE_CBR: {
            /* CBR mode has narrow bound */
            rateControl->bpsMax = rateControl->bpsTarget * BPS_MAX / BPS_BASE;
            rateControl->bpsMin = rateControl->bpsTarget * BPS_MEDIUM / BPS_BASE;
            break;
        }
        case MPP_ENC_RC_MODE_VBR:
        case MPP_ENC_RC_MODE_AVBR: {
            /* VBR mode has wide bound */
            rateControl->bpsMax = rateControl->bpsTarget * BPS_MAX / BPS_BASE;
            rateControl->bpsMin = rateControl->bpsTarget * BPS_MIN / BPS_BASE;
            break;
        }
        default: {
            /* default use CBR mode */
            rateControl->bpsMax = rateControl->bpsTarget * BPS_MAX / BPS_BASE;
            rateControl->bpsMin = rateControl->bpsTarget * BPS_MEDIUM / BPS_BASE;
            break;
        }
    }
    /* setup qp for different codec and rc_mode */
    switch (codecType) {
        case MPP_VIDEO_CodingAVC:
        case MPP_VIDEO_CodingHEVC: {
            SetQpValue(rateControl);
            break;
        }
        default: {
            break;
        }
    }
}

void CodecHdiAdapterEncode::SetQpValue(RKHdiRcSetup *rateControl)
{
    switch (rateControl->rcMode) {
        case MPP_ENC_RC_MODE_FIXQP: {
            rateControl->qpInit = FIXQP_INIT_VALUE;
            rateControl->qpMax = FIXQP_MAX_VALUE;
            rateControl->qpMin = FIXQP_MIN_VALUE;
            rateControl->qpMaxI = FIXQP_MAX_I_VALUE;
            rateControl->qpMinI = FIXQP_MIN_I_VALUE;
            rateControl->qpIp = FIXQP_IP_VALUE;
            break;
        }
        case MPP_ENC_RC_MODE_CBR:
        case MPP_ENC_RC_MODE_VBR:
        case MPP_ENC_RC_MODE_AVBR: {
            rateControl->qpInit = OTHER_QP_INIT_VALUE;
            rateControl->qpMax = OTHER_QP_MAX_VALUE;
            rateControl->qpMin = OTHER_QP_MIN_VALUE;
            rateControl->qpMaxI = OTHER_QP_MAX_I_VALUE;
            rateControl->qpMinI = OTHER_QP_MIN_I_VALUE;
            rateControl->qpIp = OTHER_QP_IP_VALUE;
            break;
        }
        default: {
            HDF_LOGE("%{public}s: unsupport encoder rc mode %{public}d", __func__, rateControl->rcMode);
            break;
        }
    }
}

int32_t CodecHdiAdapterEncode::ConfigMppPassthrough()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    PassthroughParam param;
    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    CodecType ct = VIDEO_ENCODER;
    param.key = KEY_CODEC_TYPE;
    param.val = &ct;
    param.size = sizeof(ct);

    auto ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d], key is KEY_CODEC_TYPE", __func__, ret);
        return ret;
    }

    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    RKHdiCodecMimeSetup mimeType;
    param.key = KEY_MIMETYPE;
    mimeType.mimeCodecType = MEDIA_MIMETYPE_VIDEO_AVC;
    mimeType.avcSetup.profile = AVC_SETUP_PROFILE_DEFAULT;
    mimeType.avcSetup.level = AVC_SETUP_LEVEL_DEFAULT;
    mimeType.avcSetup.cabacEn = AVC_SETUP_CABAC_EN_DEFAULT;
    mimeType.avcSetup.cabacIdc = AVC_SETUP_CABAC_IDC_DEFAULT;
    mimeType.avcSetup.trans8x8 = AVC_SETUP_TRANS_DEFAULT;
    param.val = &mimeType;
    param.size = sizeof(mimeType);

    ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d], key is KEY_MIMETYPE", __func__, ret);
        return ret;
    }

    ret = ConfigMppExtPassthrough(mimeType.mimeCodecType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] ConfigMppExtPassthrough error", __func__, ret);
        return ret;
    }

    return ret;
}

int32_t CodecHdiAdapterEncode::ConfigMppExtPassthrough(int32_t codecType)
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    PassthroughParam param;
    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    RKHdiFpsSetup fps;
    param.key = KEY_VIDEO_FRAME_RATE;
    fps.fpsInFlex = 0;
    fps.fpsInNum = ENC_SETUP_FPS_IN_NUM;
    fps.fpsOutNum = ENC_SETUP_FPS_OUT_NUM;
    fps.fpsInDen = 1;
    fps.fpsOutDen = 1;
    fps.fpsOutFlex = 0;
    param.val = &fps;
    param.size = sizeof(fps);

    auto ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d], key is KEY_VIDEO_FRAME_RATE", __func__, ret);
        return ret;
    }

    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    RKHdiRcSetup rc;
    param.key = KEY_VIDEO_RC_MODE;
    rc.rcMode = VID_CODEC_RC_VBR;
    rc.bpsTarget = width_ * height_ * BPS_TARGET / BPS_BASE * (fps.fpsOutNum / fps.fpsOutDen);
    CalcBpsRange(&rc, codecType);
    param.val = &rc;
    param.size = sizeof(rc);

    ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d], key is KEY_VIDEO_RC_MODE", __func__, ret);
        return ret;
    }

    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    param.key = KEY_EXT_ENC_VALIDATE_SETUP_RK;
    ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d], key is KEY_EXT_ENC_VALIDATE_SETUP_RK", __func__, ret);
    }

    return ret;
}

int32_t CodecHdiAdapterEncode::ConfigPortDefine()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    auto ret = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] GetParameter OMX_IndexParamPortDefinition", __func__, ret);
        return ret;
    }

    HDF_LOGI("get format: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    param.format.video.eColorFormat = AV_COLOR_FORMAT;

    ret = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] SetParameter OMX_IndexParamPortDefinition", __func__, ret);
    }
    return ret;
}

int32_t CodecHdiAdapterEncode::ConfigBitMode()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    auto ret = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] GetParameter OMX_IndexParamVideoPortFormat", __func__, ret);
        return ret;
    }

    HDF_LOGI("set Format eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;

    ret = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] SetParameter OMX_IndexParamVideoPortFormat", __func__, ret);
    }

    return ret;
}

int main(int argc, char *argv[])
{
    CommandOpt opt;
    CommandAdapterParse parse;
    if (!parse.Parse(argc, argv, opt)) {
        return 0;
    }

    if (g_core == nullptr) {
        g_core = new CodecHdiAdapterEncode();
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
