/*
 * Copyright 2023 Shenzhen Kaihong DID Co., Ltd.
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
#include <securec.h>
#include <unistd.h>
#include "codec_omx_ext.h"
#include "hdf_log.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"
using namespace std;
using namespace OHOS;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace OHOS::HDI::Codec::V3_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
#define HDF_LOG_TAG     codec_omx_hdi_enc
#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar
IDisplayBuffer *CodecHdiEncode::gralloc_ = nullptr;
CodecUtil *CodecHdiEncode::util_;
namespace {
constexpr uint32_t FRAME = 30 << 16;
constexpr uint32_t BUFFER_COUNT = 10;
constexpr uint32_t BITRATE = 3000000;
constexpr uint32_t DENOMINATOR = 2;
constexpr uint32_t NUMERATOR = 3;
constexpr int32_t INIT_BUFFER_CODE = -1;
}  // namespace
CodecHdiEncode::CodecHdiEncode() : fpIn_(nullptr), fpOut_(nullptr)
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    useBufferHandle_ = false;
    useDMABuffer_ = false;
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
    size_t t  = fread(buf, 1, width_ * height_ * NUMERATOR / DENOMINATOR, fp);
    if (feof(fp)) {
        ret = true;
    }
    filledCount = static_cast<uint32_t>(t);
    return ret;
}

bool CodecHdiEncode::Init(const CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->stride_ = AlignUp(width_);
    this->useBufferHandle_ = opt.useBufferHandle;
    this->useDMABuffer_ = opt.useDMABuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d]", width_, height_);
    // gralloc init
    gralloc_ = IDisplayBuffer::Get();
    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
        HDF_LOGE("%{public}s:failed to open file %{public}s or %{public}s", __func__, opt.fileInput.c_str(),
                 opt.fileOutput.c_str());
        return false;
    }
    // Interface init
    omxMgr_ = OHOS::HDI::Codec::V3_0::ICodecComponentManager::Get();
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
    err = omxMgr_->CreateComponent(client_, componentId_, compName, reinterpret_cast<int64_t>(this), callback_);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }
    // get version
    struct OHOS::HDI::Codec::V3_0::CompVerInfo verInfo;
    err = memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    if (err != EOK) {
        HDF_LOGE("%{public}s: memset_s verInfo err [%{public}d].", __func__, err);
        return false;
    }
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

    if (CheckAndUseDMABuffer() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigUseBufferHandle error", __func__);
        return false;
    }
    return true;
}

int32_t CodecHdiEncode::CheckSupportBufferType(PortIndex portIndex, CodecBufferType codecBufferType)
{
    //get support buffer
    SupportBufferType param;
    std::vector<int8_t> inVec, outVec;
    if (util_->InitParamInOhos(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.portIndex = static_cast<uint32_t>(portIndex);
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed get parameter with portIndex %{public}d and ret %{public}d ",
                 __func__, portIndex, err);
    }
    util_->VectorToObject(outVec, param);
    if (!(param.bufferTypes & codecBufferType)) {
        HDF_LOGE("%{public}s unSupport bufferType %{public}d ,ret is  %{public}d",
                 __func__, codecBufferType,  param.bufferTypes);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::CheckAndUseDMABuffer()
{
    if (!useDMABuffer_) {
        return HDF_SUCCESS;
    }
    auto err = CheckSupportBufferType(PortIndex::PORT_INDEX_OUTPUT, CODEC_BUFFER_TYPE_DMA_MEM_FD);
    if (err != HDF_SUCCESS) {
        return  HDF_FAILURE;
    }
    return err;
}

int32_t CodecHdiEncode::CheckAndUseBufferHandle()
{
    if (!useBufferHandle_) {
        return HDF_SUCCESS;
    }

    SupportBufferType param;
    if (util_->InitParamInOhos(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);

    auto err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PORT_INDEX_OUTPUT, index is OMX_IndexParamSupportBufferType", __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    if (util_->InitParamInOhos(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    util_->ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PORT_INDEX_INPUT, index is OMX_IndexParamSupportBufferType", __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    GetBufferHandleUsageParams usage;
    if (util_->InitParamInOhos(usage) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    usage.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    util_->ObjectToVector(usage, inVec);
    err = client_->GetParameter(OMX_IndexParamGetBufferHandleUsage, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PORT_INDEX_INPUT, index is OMX_IndexParamGetBufferHandleUsage", __func__);
        return err;
    }
    util_->VectorToObject(outVec, usage);

    UseBufferType type;
    if (util_->InitParamInOhos(type) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    type.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    type.bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
    util_->ObjectToVector(type, inVec);
    err = client_->SetParameter(OMX_IndexParamUseBufferType, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PORT_INDEX_INPUT, index is OMX_IndexParamUseBufferType", __func__);
        return err;
    }
    return err;
}

bool CodecHdiEncode::UseBuffers()
{
    // commad to IDLE
    auto err = client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with CODEC_COMMAND_STATE_SET:CODEC_STATE_IDLE", __func__);
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
    CodecStateType status = CODEC_STATE_INVALID;
    err = client_->GetState(status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState err [%{public}x]", __func__, err);
        return false;
    }

    // wait loaded
    if (status != CODEC_STATE_IDLE) {
        HDF_LOGI("Wait for CODEC_STATE_LOADED status");
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(portIndex);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }
    util_->VectorToObject(outVec, param);

    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], buffer count [%{public}d], "
             "portEnable[%{public}d], ret [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);
    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        bufferSize = width_ * height_ * NUMERATOR / DENOMINATOR;
    } else if (bufferSize == 0) {
        bufferSize = width_ * height_;
        HDF_LOGI("bufferSize[%{public}d], width[%{public}d], height[%{public}d]", bufferSize, width_, height_);
    }
    if (useBufferHandle_ && portIndex == PortIndex::PORT_INDEX_INPUT) {
        err = UseDynaBuffer(bufferCount, bufferSize);
    } else if (useDMABuffer_ && portIndex == PortIndex::PORT_INDEX_OUTPUT) {
        err = UseDMABuffer(portIndex, bufferCount, bufferSize);
    } else {
        err = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    }

    if (err != HDF_SUCCESS) {
        return err;
    }

    // if port is disable, changed to enable
    if (!portEnable) {
        err = client_->SendCommand(CODEC_COMMAND_PORT_ENABLE, static_cast<uint32_t>(portIndex), {});
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s SendCommand OMX_CommandPortEnable::PORT_INDEX_INPUT error", __func__);
            return err;
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::UseDMABuffer(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("UseDMABuffer bufferCount <= 0 or bufferSize <= 0");
        return HDF_ERR_INVALID_PARAM;
    }
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.version.majorVersion = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_DMA_MEM_FD;
        omxBuffer->fd = INIT_BUFFER_CODE;
        omxBuffer->bufferhandle = nullptr;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = INIT_BUFFER_CODE;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;

        OmxCodecBuffer outBuffer;
        auto err = client_->AllocateBuffer(static_cast<uint32_t>(portIndex), *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            return err;
        }
        omxBuffer->bufferId = outBuffer.bufferId;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->portIndex = portIndex;
        omxBuffers_.insert(std::make_pair(omxBuffer->bufferId, bufferInfo));
        unUsedOutBuffers_.push_back(omxBuffer->bufferId);

        const void *addr = mmap(nullptr, static_cast<size_t>(bufferInfo->omxBuffer->allocLen),
                                PROT_READ | PROT_WRITE, MAP_SHARED, outBuffer.fd, 0);
        if (addr == nullptr) {
            HDF_LOGE("%{public}s mmap fail fd %{public}d", __func__, outBuffer.fd);
            return HDF_FAILURE;
        } else {
            addrs_[omxBuffer->bufferId] = addr;
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
        omxBuffer->version.version.majorVersion = 1;
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
            omxBuffer->type = OHOS::HDI::Codec::V3_0::READ_ONLY_TYPE;
            spSharedMem->MapReadAndWriteAshmem();
        } else {
            omxBuffer->type = OHOS::HDI::Codec::V3_0::READ_WRITE_TYPE;
            spSharedMem->MapReadOnlyAshmem();
        }
        OmxCodecBuffer outBuffer;
        auto err = client_->UseBuffer(static_cast<uint32_t>(portIndex), *omxBuffer.get(), outBuffer);
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
        omxBuffer->version.version.majorVersion = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_DYNAMIC_HANDLE;
        omxBuffer->fd = -1;
        omxBuffer->bufferhandle = nullptr;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;

        OmxCodecBuffer outBuffer;
        auto err = client_->UseBuffer(static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT),
            *omxBuffer.get(), outBuffer);
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
    (void)client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, {});

    // All the buffer must be released, otherwise the component will wait
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        (void)client_->FreeBuffer(static_cast<uint32_t>(bufferInfo->portIndex), *bufferInfo->omxBuffer.get());
        iter = omxBuffers_.erase(iter);
    }
    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    CodecStateType status = CODEC_STATE_INVALID;
    auto err = client_->GetState(status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
        return;
    }
    // wait
    if (status != CODEC_STATE_LOADED) {
        HDF_LOGI("Wait for CODEC_STATE_LOADED status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI("status is %{public}d", status);
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
    if (nSize != 0) {
        bufferID = unUsedInBuffers_.front();
        unUsedInBuffers_.pop_front();
    }
    return bufferID;
}

int32_t CodecHdiEncode::GetComponentName(std::string &compName)
{
    OHOS::HDI::Codec::V3_0::AvCodecRole role = OHOS::HDI::Codec::V3_0::AvCodecRole::MEDIA_ROLETYPE_VIDEO_AVC;
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
        if (cap.type == OHOS::HDI::Codec::V3_0::CodecType::VIDEO_ENCODER && cap.role == role) {
            compName = cap.compName;
            err = HDF_SUCCESS;
        }
    }
    return err;
}

void CodecHdiEncode::Run()
{
    auto err = client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, {});
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with CODEC_COMMAND_STATE_SET:CODEC_STATE_IDLE", __func__);
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
        bufferInfo->omxBuffer->bufferhandle = nullptr;
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    while (!this->exit_) {
        usleep(10000);  // 10000 for wait 10ms
    }
    (void)client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
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
            endFlag = this->ReadOneFrame(fpIn_, static_cast<char *>(bufferHandle->virAddr),
                bufferInfo->omxBuffer->filledLen);
            gralloc_->Unmap(*bufferHandle);
            bufferInfo->omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
        }
    } else {
        // read data from ashmem
        void *sharedAddr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(0, 0));
        endFlag = this->ReadOneFrame(fpIn_, static_cast<char *>(sharedAddr), bufferInfo->omxBuffer->filledLen);
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
    for (uint32_t i = 0; i < BUFFER_COUNT; i++) {
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

int32_t CodecHdiEncode::EventHandler(OHOS::HDI::Codec::V3_0::CodecEventType event,
    const OHOS::HDI::Codec::V3_0::EventInfo &info)
{
    if (event == CODEC_EVENT_CMD_COMPLETE) {
        CodecCommandType cmd = (CodecCommandType)info.data1;
        if (CODEC_COMMAND_STATE_SET == cmd) {
            HDF_LOGI("CODEC_COMMAND_STATE_SET reached, status is %{public}d", info.data2);
            this->OnStatusChanged();
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    HDF_LOGI("OnEmptyBufferDone, bufferId [%{public}d]", buffer.bufferId);
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
    HDF_LOGI("OnFillBufferDone, bufferId [%{public}d]", buffer.bufferId);
    if (exit_) {
        return HDF_SUCCESS;
    }

    auto iter = omxBuffers_.find(buffer.bufferId);
    if (iter == omxBuffers_.end() || !iter->second) {
        return HDF_SUCCESS;
    }

    auto bufferInfo = iter->second;
    const void *addr;
    if (useDMABuffer_) {
        auto ret = addrs_.find(buffer.bufferId);
        if (ret != addrs_.end()) {
            addr = ret->second;
        } else {
            HDF_LOGI("OnFillBufferDone, get addr fail [%{public}d]", buffer.bufferId);
            return HDF_FAILURE;
        }
    } else {
        addr = bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset);
    }
    // save to file
    (void)fwrite(addr, 1, buffer.filledLen, fpOut_);
    (void)fflush(fpOut_);

    if (buffer.flag & OMX_BUFFERFLAG_EOS) {
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    util_->setParmValue(param, width_, height_, stride_);
    param.format.video.eColorFormat = AV_COLOR_FORMAT;
    util_->ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamPortDefinition, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with INPUT, OMX_IndexParamPortDefinition",  __func__);
        return err;
    }

    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    util_->ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OUTPUT, OMX_IndexParamPortDefinition", __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    util_->setParmValue(param, width_, height_, stride_);
    util_->ObjectToVector(param, inVec);
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamVideoPortFormat, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat");
        return err;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("set Format PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;

    util_->ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamVideoPortFormat, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }

    OMX_VIDEO_PARAM_BITRATETYPE bitRate;
    util_->InitParam(bitRate);
    bitRate.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    util_->ObjectToVector(bitRate, inVec);
    err = client_->GetParameter(OMX_IndexParamVideoBitrate, inVec, outVec);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s OMX_GetParameter portindex = PORT_INDEX_OUTPUT, err[%{public}d]", __func__, err);
        return err;
    }
    util_->VectorToObject(outVec, bitRate);
    HDF_LOGI("get PORT_INDEX_OUTPUT:OMX_IndexParamVideoBitrate, bit_mode[%{public}d], biterate:[%{publicd}d]",
             bitRate.eControlRate, bitRate.nTargetBitrate);

    bitRate.eControlRate = OMX_Video_ControlRateConstant;
    bitRate.nTargetBitrate = BITRATE;
    util_->ObjectToVector(bitRate, inVec);
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