/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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
#include <hdf_log.h>
#include <securec.h>
#include <unistd.h>
#include "codec_omx_ext.h"

using namespace std;
using namespace OHOS;
using OHOS::sptr;
using OHOS::HDI::Codec::V1_0::CodecCompCapability;
using OHOS::HDI::Base::HdiBufferHandle;
#define HDF_LOG_TAG     codec_omx_hdi_enc
#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar
OHOS::HDI::Display::V1_0::IDisplayGralloc *CodecHdiEncode::gralloc_ = nullptr;
namespace {
constexpr int32_t FRAME = 30 << 16;
constexpr int32_t BUFFER_COUNT = 10;
constexpr int32_t BITRATE = 3000000;
constexpr int32_t DENOMINATOR = 2;
constexpr int32_t NUMERATOR = 3;
}  // namespace
CodecHdiEncode::CodecHdiEncode() : fpIn_(nullptr), fpOut_(nullptr)
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    useBufferHandle_ = false;
    width_ = 0;
    height_ = 0;
    componentId_ = 0;
}

CodecHdiEncode::~CodecHdiEncode()
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

void CodecHdiEncode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiEncode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

bool CodecHdiEncode::ReadOneFrame(FILE *fp, char *buf, uint32_t &filledCount)
{
    bool ret = false;
    filledCount = fread(buf, 1, width_ * height_ * NUMERATOR / DENOMINATOR, fp);
    if (feof(fp)) {
        ret = true;
    }
    return ret;
}

bool CodecHdiEncode::Init(const CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->stride_ = AlignUp(width_);
    this->useBufferHandle_ = opt.useBuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d]", width_, height_);
    // gralloc init
    gralloc_ = OHOS::HDI::Display::V1_0::IDisplayGralloc::Get();

    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
        HDF_LOGE("%{public}s:failed to open file %{public}s or %{public}s", __func__, opt.fileInput.c_str(),
                 opt.fileOutput.c_str());
        return false;
    }
    // Interface init
    omxMgr_ = OHOS::HDI::Codec::V1_0::ICodecComponentManager::Get();
    callback_ = new CodecHdiCallback(shared_from_this());
    if ((omxMgr_ == nullptr) || (callback_ == nullptr)) {
        HDF_LOGE("%{public}s:omxMgr_ or callback_ is null", __func__);
        return false;
    }
    std::string compName("");
    auto err = GetComponentName(compName);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetComponentName", __func__);
        return false;
    }
    // create a component
    err = omxMgr_->CreateComponent(client_, componentId_, compName.c_str(), (int64_t)this, callback_);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }
    // get version
    struct OHOS::HDI::Codec::V1_0::CompVerInfo verInfo;
    (void)memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    err = client_->GetComponentVersion(verInfo);
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
    // set input width, height and COLOR, set ouput port width and height
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
    param.portIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    std::vector<int8_t> inVec, outVec;
    ObjectToVector(param, inVec);

    auto err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:PORT_INDEX_OUTPUT, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    VectorToObject(outVec, param);

    InitParamInOhos(param);
    param.portIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:PORT_INDEX_INPUT, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    VectorToObject(outVec, param);

    GetBufferHandleUsageParams usage;
    InitParamInOhos(usage);
    usage.portIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    ObjectToVector(usage, inVec);
    err = client_->GetParameter(OMX_IndexParamGetBufferHandleUsage, inVec, outVec);
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamGetBufferHandleUsage:PORT_INDEX_INPUT, err [%{public}x], usage[%{public}d]",
        err, usage.usage);
    if (err != HDF_SUCCESS) {
        return err;
    }
    VectorToObject(outVec, usage);

    UseBufferType type;
    InitParamInOhos(type);
    type.portIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    type.bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
    ObjectToVector(type, inVec);
    err = client_->SetParameter(OMX_IndexParamUseBufferType, inVec);
    HDF_LOGI("OMX_SetParameter:OMX_IndexParamUseBufferType:PORT_INDEX_INPUT, err [%{public}x]", err);
    return err;
}

bool CodecHdiEncode::UseBuffers()
{
    // commad to IDLE
    auto err =
        client_->SendCommand(OHOS::HDI::Codec::V1_0::OMX_CommandStateSet, OHOS::HDI::Codec::V1_0::OMX_StateIdle, {});
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
    OHOS::HDI::Codec::V1_0::OMX_STATETYPE status;
    err = client_->GetState(status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState err [%{public}x]", __func__, err);
        return false;
    }

    // wait loaded
    if (status != OHOS::HDI::Codec::V1_0::OMX_StateIdle) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }
    return true;
}

int32_t CodecHdiEncode::UseBufferOnPort(PortIndex portIndex)
{
    HDF_LOGI("%{public}s enter, portIndex = %{public}d", __func__, portIndex);
    int bufferSize = 0;
    int bufferCount = 0;
    bool portEnable = false;

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)portIndex;
    std::vector<int8_t> inVec, outVec;
    ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }
    VectorToObject(outVec, param);

    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], buffer count [%{public}d], "
             "portEnable[%{public}d], err [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);
    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        bufferSize = width_ * height_ * NUMERATOR / DENOMINATOR;
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
        err = client_->SendCommand(OHOS::HDI::Codec::V1_0::OMX_CommandPortEnable, (uint32_t)portIndex, {});
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
        omxBuffer->fd = fd;
        omxBuffer->bufferhandle = nullptr;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;
        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            omxBuffer->type = OHOS::HDI::Codec::V1_0::READ_ONLY_TYPE;
            spSharedMem->MapReadAndWriteAshmem();
        } else {
            omxBuffer->type = OHOS::HDI::Codec::V1_0::READ_WRITE_TYPE;
            spSharedMem->MapReadOnlyAshmem();
        }
        OmxCodecBuffer outBuffer;
        auto err = client_->UseBuffer((uint32_t)portIndex, *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            spSharedMem->UnmapAshmem();
            spSharedMem->CloseAshmem();
            spSharedMem = nullptr;
            return err;
        }

        omxBuffer->bufferId = outBuffer.bufferId;
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
        omxBuffer->fd = -1;
        omxBuffer->bufferhandle = nullptr;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;

        OmxCodecBuffer outBuffer;
        auto err = client_->UseBuffer((uint32_t)PortIndex::PORT_INDEX_INPUT, *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  PORT_INDEX_INPUT", __func__);
            return err;
        }

        omxBuffer->bufferId = outBuffer.bufferId;
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
    (void)client_->SendCommand(OHOS::HDI::Codec::V1_0::OMX_CommandStateSet, OHOS::HDI::Codec::V1_0::OMX_StateLoaded,
                               {});

    // All the buffer must be released, otherwise the component will wait
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        (void)client_->FreeBuffer((uint32_t)bufferInfo->portIndex, *bufferInfo->omxBuffer.get());
        iter = omxBuffers_.erase(iter);
    }
    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    OHOS::HDI::Codec::V1_0::OMX_STATETYPE status = OHOS::HDI::Codec::V1_0::OMX_StateInvalid;
    auto err = client_->GetState(status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
        return;
    }

    // wait
    if (status != OHOS::HDI::Codec::V1_0::OMX_StateLoaded) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }
}

void CodecHdiEncode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
}

bool CodecHdiEncode::FillAllTheBuffer()
{
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("fill bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter != omxBuffers_.end()) {
            auto bufferInfo = iter->second;
            auto err = client_->FillThisBuffer(*bufferInfo->omxBuffer.get());
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

int32_t CodecHdiEncode::GetComponentName(std::string &compName)
{
    OHOS::HDI::Codec::V1_0::AvCodecRole role = OHOS::HDI::Codec::V1_0::AvCodecRole::MEDIA_ROLETYPE_VIDEO_AVC;
    int32_t count = 0;
    auto err = omxMgr_->GetComponentNum(count);
    if (err != HDF_SUCCESS || count <= 0) {
        HDF_LOGE("%{public}s GetComponentNum return %{public}d, count = %{public}d", __func__, err, count);
        return HDF_FAILURE;
    }
    std::vector<CodecCompCapability> caps;
    err = omxMgr_->GetComponentCapabilityList(caps, count);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetComponentCapabilityList return %{public}d", __func__, err);
        return err;
    }
    err = HDF_FAILURE;
    for (auto cap : caps) {
        if (cap.type == OHOS::HDI::Codec::V1_0::CodecType::VIDEO_ENCODER && cap.role == role) {
            compName = cap.compName;
            err = HDF_SUCCESS;
        }
    }
    return err;
}

void CodecHdiEncode::Run()
{
    auto err = client_->SendCommand(OHOS::HDI::Codec::V1_0::OMX_CommandStateSet,
                                    OHOS::HDI::Codec::V1_0::OMX_StateExecuting, {});
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with OMX_CommandStateSet:OMX_StateIdle", __func__);
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
            usleep(10000);  // 10000 for wait 10ms
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
        err = client_->EmptyThisBuffer(*bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    while (!this->exit_) {
        usleep(10000);  // 10000 for wait 10ms
        continue;
    }
    (void)client_->SendCommand(OHOS::HDI::Codec::V1_0::OMX_CommandStateSet, OHOS::HDI::Codec::V1_0::OMX_StateIdle, {});
    return;
}

bool CodecHdiEncode::FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &endFlag)
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
            endFlag = this->ReadOneFrame(fpIn_, (char *)bufferHandle->virAddr, bufferInfo->omxBuffer->filledLen);
            gralloc_->Unmap(*bufferHandle);
            bufferInfo->omxBuffer->bufferhandle = new HdiBufferHandle(*bufferHandle);
        }
    } else {
        // read data from ashmem
        void *sharedAddr = (void *)bufferInfo->avSharedPtr->ReadFromAshmem(0, 0);
        endFlag = this->ReadOneFrame(fpIn_, (char *)sharedAddr, bufferInfo->omxBuffer->filledLen);
    }
    bufferInfo->omxBuffer->offset = 0;
    if (endFlag) {
        bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
    }

    return true;
}

int32_t CodecHdiEncode::CreateBufferHandle()
{
    if (gralloc_ == nullptr) {
        HDF_LOGE("%{public}s gralloc_ is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    AllocInfo alloc = {.width = this->stride_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};

    int32_t err = HDF_SUCCESS;
    for (size_t i = 0; i < BUFFER_COUNT; i++) {
        BufferHandle *bufferHandle = nullptr;
        err = gralloc_->AllocMem(alloc, bufferHandle);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s AllocMem fail", __func__);
            return err;
        }
        bufferHandles_.emplace(std::make_pair(i, bufferHandle));
        freeBufferHandles_.push_back(i);
    }
    return err;
}
int32_t CodecHdiEncode::EventHandler(OHOS::HDI::Codec::V1_0::OMX_EVENTTYPE event,
                                     const OHOS::HDI::Codec::V1_0::EventInfo &info)
{
    switch (event) {
        case OHOS::HDI::Codec::V1_0::OMX_EventCmdComplete: {
            OHOS::HDI::Codec::V1_0::OMX_COMMANDTYPE cmd = (OHOS::HDI::Codec::V1_0::OMX_COMMANDTYPE)info.data1;
            if (OHOS::HDI::Codec::V1_0::OMX_CommandStateSet == cmd) {
                HDF_LOGI("OMX_CommandStateSet reached, status is %{public}d", info.data2);
                this->OnStatusChanged();
            }
            break;
        }

        default:
            break;
    }

    return HDF_SUCCESS;
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
    const void *addr = bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset);
    // save to file
    (void)fwrite(addr, 1, buffer.filledLen, fpOut_);
    (void)fflush(fpOut_);

    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }
    auto err = client_->FillThisBuffer(*bufferInfo->omxBuffer.get());
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
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    std::vector<int8_t> inVec, outVec;
    ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    VectorToObject(outVec, param);

    HDF_LOGI("PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    param.format.video.eColorFormat = AV_COLOR_FORMAT;
    ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamPortDefinition, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }

    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    VectorToObject(outVec, param);

    HDF_LOGI("PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamPortDefinition, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::ConfigBitMode()
{
    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    std::vector<int8_t> inVec, outVec;
    ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamVideoPortFormat, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat");
        return err;
    }
    VectorToObject(outVec, param);

    HDF_LOGI("set Format PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;

    ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamVideoPortFormat, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }

    OMX_VIDEO_PARAM_BITRATETYPE bitRate;
    InitParam(bitRate);
    bitRate.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    ObjectToVector(bitRate, inVec);
    err = client_->GetParameter(OMX_IndexParamVideoBitrate, inVec, outVec);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s OMX_GetParameter portindex = PORT_INDEX_OUTPUT, err[%{public}d]", __func__, err);
        return err;
    }
    VectorToObject(outVec, bitRate);
    HDF_LOGI("get PORT_INDEX_OUTPUT:OMX_IndexParamVideoBitrate, bit_mode[%{public}d], biterate:[%{publicd}d]",
             bitRate.eControlRate, bitRate.nTargetBitrate);

    bitRate.eControlRate = OMX_Video_ControlRateConstant;
    bitRate.nTargetBitrate = BITRATE;
    ObjectToVector(bitRate, inVec);
    err = client_->SetParameter(OMX_IndexParamVideoBitrate, inVec);
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
    auto core = std::make_shared<CodecHdiEncode>();
    if (!core->Init(opt)) {
        core = nullptr;
        return HDF_FAILURE;
    }

    if (!core->Configure()) {
        core = nullptr;
        return HDF_FAILURE;
    }

    if (!core->UseBuffers()) {
        core = nullptr;
        return HDF_FAILURE;
    }

    core->Run();

    core->FreeBuffers();

    core->Release();
    core = nullptr;
}