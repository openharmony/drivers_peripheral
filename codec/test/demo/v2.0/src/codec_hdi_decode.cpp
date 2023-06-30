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

#include "codec_hdi_decode.h"
#include <hdf_base.h>
#include <unistd.h>
#include "codec_component_manager.h"
#include "codec_omx_ext.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
namespace {
constexpr uint32_t FD_SIZE = sizeof(int);
constexpr uint32_t FRAME = 30 << 16;
constexpr uint32_t DENOMINATOR = 2;
constexpr uint32_t NUMERATOR = 3;
constexpr uint32_t MAX_WAIT_COUNT = 3;
}  // namespace
#define HDF_LOG_TAG codec_omx_hdi_dec
IDisplayBuffer *CodecHdiDecode::buffer_ = nullptr;

#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar

static CodecHdiDecode *g_core = nullptr;
CodecHdiDecode::CodecHdiDecode()
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    width_ = 0;
    height_ = 0;
    codecMime_ = CodecMime::AVC;
    count_ = 0;
    useBufferHandle_ = false;
    componentId_ = 0;
    reader_ = nullptr;
    color_ = ColorFormat::YUV420SP;
    omxColorFormat_ = OMX_COLOR_FormatYUV420SemiPlanar;
}

CodecHdiDecode::~CodecHdiDecode()
{
    if (ioOut_.is_open()) {
        ioOut_.close();
    }
    if (ioIn_.is_open()) {
        ioIn_.close();
    }
}

void CodecHdiDecode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiDecode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

int CodecHdiDecode::GetYuvSize()
{
    return width_ * height_ * NUMERATOR / DENOMINATOR;
}

bool CodecHdiDecode::Init(CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->codecMime_ = opt.codec;
    this->stride_ = AlignUp(opt.width);
    this->useBufferHandle_ = opt.useBuffer;
    color_ = opt.colorForamt;
    if (color_ == ColorFormat::RGBA8888) {
        omxColorFormat_ = static_cast<OMX_COLOR_FORMATTYPE>(CODEC_COLOR_FORMAT_RGBA8888);
    } else if (color_ == ColorFormat::BGRA8888) {
        omxColorFormat_ = OMX_COLOR_Format32bitBGRA8888;
    }
    HDF_LOGI("width[%{public}d], height[%{public}d],stride_[%{public}d],infile[%{public}s],outfile[%{public}s]", width_,
             height_, stride_, opt.fileInput.c_str(), opt.fileOutput.c_str());

    // gralloc init
    buffer_ = IDisplayBuffer::Get();
    reader_ = CodecPacketReader::GetPacketReader(opt.codec);
    ioIn_.open(opt.fileInput, std::ios_base::binary);
    ioOut_.open(opt.fileOutput, std::ios_base::binary | std::ios_base::trunc);
    if (!ioOut_.is_open() || !ioIn_.is_open()) {
        HDF_LOGE("%{public}s failed to open file %{public}s or %{public}s", __func__, opt.fileInput.c_str(),
                 opt.fileOutput.c_str());
        return false;
    }

    omxMgr_ = GetCodecComponentManager();

    callback_ = CodecCallbackTypeGet(nullptr);
    if ((omxMgr_ == nullptr) || (callback_ == nullptr)) {
        HDF_LOGE("%{public}s omxMgr_ is null or callback_ is null", __func__);
        return false;
    }

    callback_->EventHandler = &CodecHdiDecode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiDecode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiDecode::OnFillBufferDone;
    int32_t err = GetComponent();
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }

    struct CompVerInfo verInfo;
    err = memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    if (err != EOK) {
        HDF_LOGE("%{public}s: memset_s verInfo err [%{public}d].", __func__, err);
        return false;
    }
    err = client_->GetComponentVersion(client_, &verInfo);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }

    return true;
}

int32_t CodecHdiDecode::ConfigPortDefine()
{
    // set width and height on input port
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    auto err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  PortIndex::PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition", __func__);
        return err;
    }
    HDF_LOGI("PortIndex::PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat = %{public}d ",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    err =
        client_->SetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition", __func__);
        return err;
    }

    // set width, height and color format on output port
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    HDF_LOGI("PortIndex::PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    param.format.video.eColorFormat = omxColorFormat_;
    err =
        client_->SetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with PortIndex::PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    return err;
}
bool CodecHdiDecode::Configure()
{
    if (ConfigPortDefine() != HDF_SUCCESS) {
        return false;
    }

    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    auto err = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                     sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT", __func__);
        return false;
    }
    HDF_LOGI("set Format PortIndex::PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;  // 30fps,Q16 format
    switch (codecMime_) {
        case CodecMime::AVC:
            param.eCompressionFormat = OMX_VIDEO_CodingAVC;  // H264
            break;
        case CodecMime::HEVC:
            param.eCompressionFormat = (OMX_VIDEO_CODINGTYPE)CODEC_OMX_VIDEO_CodingHEVC;  // H265
            break;
        case CodecMime::MPEG4:
            param.eCompressionFormat = OMX_VIDEO_CodingMPEG4;  // H264
            break;
        case CodecMime::VP9:
            param.eCompressionFormat = (OMX_VIDEO_CODINGTYPE)CODEC_OMX_VIDEO_CodingVP9;  // H264
            break;
        default:
            break;
    }

    err = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, reinterpret_cast<int8_t *>(&param),
                                sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with PortIndex::PORT_INDEX_INPUT", __func__);
        return false;
    }

    err = CheckAndUseBufferHandle();
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with CheckAndUseBufferHandle", __func__);
        return false;
    }
    return true;
}

int32_t CodecHdiDecode::CheckAndUseBufferHandle()
{
    if (!useBufferHandle_) {
        return HDF_SUCCESS;
    }
    SupportBufferType param;
    InitParamInOhos(param);
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);

    auto err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, reinterpret_cast<int8_t *>(&param),
                                     sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:kPortIndexInput, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    InitParamInOhos(param);
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, reinterpret_cast<int8_t *>(&param),
                                sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:kPortIndexOutput, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    GetBufferHandleUsageParams usage;
    InitParamInOhos(usage);
    usage.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    err = client_->GetParameter(client_, OMX_IndexParamGetBufferHandleUsage, reinterpret_cast<int8_t *>(&usage),
                                sizeof(usage));
    HDF_LOGI("OMX_GetParameter:GetBufferHandleUsage:kPortIndexOutput, err [%{public}x], usage[%{public}" PRIu64 "]",
             err, usage.usage);
    if (err != HDF_SUCCESS) {
        return err;
    }
    UseBufferType type;
    InitParamInOhos(type);
    type.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    type.bufferType = CODEC_BUFFER_TYPE_HANDLE;
    err = client_->SetParameter(client_, OMX_IndexParamUseBufferType, reinterpret_cast<int8_t *>(&type), sizeof(type));
    HDF_LOGI("OMX_SetParameter:OMX_IndexParamUseBufferType:kPortIndexOutput, err [%{public}x]", err);
    return err;
}

bool CodecHdiDecode::UseBuffers()
{
    HDF_LOGI("...command to IDLE....");
    auto err = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with OMX_CommandStateSet:OMX_StateIdle", __func__);
        return false;
    }

    err = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort PortIndex::PORT_INDEX_INPUT error", __func__);
        return false;
    }

    err = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort PortIndex::PORT_INDEX_OUTPUT error", __func__);
        return false;
    }

    HDF_LOGI("Wait for OMX_StateIdle status");
    OMX_STATETYPE status;
    err = client_->GetState(client_, &status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState err [%{public}x]", __func__, err);
        return false;
    }
    if (status != OMX_StateIdle) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }

    return true;
}

int32_t CodecHdiDecode::UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        return HDF_ERR_INVALID_PARAM;
    }
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.s.nVersionMajor = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = AshmemCreate(0, bufferSize);
        shared_ptr<Ashmem> sharedMem = make_shared<Ashmem>(fd, bufferSize);
        omxBuffer->bufferLen = FD_SIZE;
        omxBuffer->buffer = reinterpret_cast<uint8_t *>(fd);
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
        auto err = client_->UseBuffer(client_, static_cast<uint32_t>(portIndex), omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
            return err;
        }
        omxBuffer->bufferLen = 0;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->avSharedPtr = sharedMem;
        bufferInfo->portIndex = portIndex;
        omxBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        if (portIndex == PortIndex::PORT_INDEX_INPUT) {
            unUsedInBuffers_.push_back(omxBuffer->bufferId);
        } else {
            unUsedOutBuffers_.push_back(omxBuffer->bufferId);
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::UseBufferOnPort(PortIndex portIndex)
{
    HDF_LOGI("%{public}s enter, portIndex = %{public}d", __func__, portIndex);

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = static_cast<OMX_U32>(portIndex);
    auto err =
        client_->GetParameter(client_, OMX_IndexParamPortDefinition, reinterpret_cast<int8_t *>(&param), sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }

    int bufferSize = param.nBufferSize;
    int bufferCount = param.nBufferCountActual;
    bool portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], "
             "buffer count [%{public}d], portEnable[%{public}d], err [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);

    {
        OMX_PARAM_BUFFERSUPPLIERTYPE param;
        InitParam(param);
        param.nPortIndex = static_cast<uint32_t>(portIndex);
        err = client_->GetParameter(client_, OMX_IndexParamCompBufferSupplier, reinterpret_cast<int8_t *>(&param),
                                    sizeof(param));
        HDF_LOGI("param.eBufferSupplier[%{public}d] err [%{public}d]", param.eBufferSupplier, err);
    }
    if (useBufferHandle_ && portIndex == PortIndex::PORT_INDEX_OUTPUT) {
        err = UseBufferHandle(bufferCount, bufferSize);
    } else {
        err = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    }

    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort err[%{public}x]", __func__, err);
        return err;
    }
    // set port enable
    if (!portEnable) {
        err = client_->SendCommand(client_, OMX_CommandPortEnable, static_cast<uint32_t>(portIndex), NULL, 0);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s SendCommand OMX_CommandPortEnable::PortIndex::PORT_INDEX_INPUT error", __func__);
            return err;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::UseBufferHandle(int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0 || buffer_ == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    PixelFormat pixForamt = PIXEL_FMT_YCBCR_420_SP;
    if (color_ == ColorFormat::RGBA8888) {
        pixForamt = PIXEL_FMT_RGBA_8888;
    } else if (color_ == ColorFormat::BGRA8888) {
        pixForamt = PIXEL_FMT_BGRA_8888;
    }
    AllocInfo alloc = {.width = this->width_,
        .height = this->height_,
        .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
        .format = pixForamt};

    for (int i = 0; i < bufferCount; i++) {
        int32_t ret = HDF_SUCCESS;
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.s.nVersionMajor = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle = nullptr;
        ret = buffer_->AllocMem(alloc, bufferHandle);
        HDF_LOGI("%{public}s AlloceMem ret val err[%{public}d]", __func__, ret);
        if (DISPLAY_SUCCESS != ret) {
            HDF_LOGE("%{public}s AllocMem error", __func__);
            return ret;
        }
        size_t handleSize =
            sizeof(BufferHandle) + (sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts));
        omxBuffer->bufferLen = handleSize;
        omxBuffer->buffer = reinterpret_cast<uint8_t *>(bufferHandle);
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;  // check use -1 first with no window
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;
        auto err = client_->UseBuffer(client_, static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT), omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  output port]", __func__);
            return err;
        }
        omxBuffer->bufferLen = 0;
        HDF_LOGI("UseBuffer returned bufferID [%{public}d]", omxBuffer->bufferId);

        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>();
        bufferInfo->omxBuffer = omxBuffer;
        bufferInfo->setBufferHandle(bufferHandle);
        bufferInfo->portIndex = PortIndex::PORT_INDEX_OUTPUT;
        omxBuffers_.emplace(std::make_pair(omxBuffer->bufferId, bufferInfo));
        unUsedOutBuffers_.push_back(omxBuffer->bufferId);
    }
    return HDF_SUCCESS;
}

void CodecHdiDecode::FreeBuffers()
{
    // command to loaded
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateLoaded, nullptr, 0);

    // release all the buffers
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        iter = omxBuffers_.erase(iter);
        (void)client_->FreeBuffer(client_, static_cast<uint32_t>(bufferInfo->portIndex), bufferInfo->omxBuffer.get());
        bufferInfo = nullptr;
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

void CodecHdiDecode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    CodecComponentTypeRelease(client_);
    client_ = nullptr;
    CodecComponentManagerRelease();
}

bool CodecHdiDecode::FillAllTheBuffer()
{
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("fill bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter != omxBuffers_.end()) {
            auto bufferInfo = iter->second;
            auto buffer = bufferInfo->omxBuffer.get();
            if (bufferInfo->bufferHandle != nullptr) {
                buffer->buffer = reinterpret_cast<uint8_t *>(bufferInfo->bufferHandle);
                buffer->bufferLen = sizeof(BufferHandle) + sizeof(int32_t) * (bufferInfo->bufferHandle->reserveFds +
                                                                              bufferInfo->bufferHandle->reserveInts);
            }

            auto err = client_->FillThisBuffer(client_, buffer);
            if (err != HDF_SUCCESS) {
                HDF_LOGE("%{public}s FillThisBuffer error", __func__);
                return false;
            }
        }
    }
    return true;
}

int CodecHdiDecode::GetFreeBufferId()
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

int32_t CodecHdiDecode::GetComponent()
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
        if (caps[i].type != VIDEO_DECODER) {
            continue;
        }
        if (((caps[i].role == MEDIA_ROLETYPE_VIDEO_AVC) && (codecMime_ == CodecMime::AVC)) ||
            ((caps[i].role == MEDIA_ROLETYPE_VIDEO_HEVC) && (codecMime_ == CodecMime::HEVC)) ||
            ((caps[i].role == MEDIA_ROLETYPE_VIDEO_VP9) && (codecMime_ == CodecMime::VP9)) ||
            ((caps[i].role == MEDIA_ROLETYPE_VIDEO_MPEG4) && (codecMime_ == CodecMime::MPEG4))) {
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

void CodecHdiDecode::Run()
{
    HDF_LOGI("...command to OMX_StateExecuting....");
    auto err = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateExecuting, NULL, 0);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with OMX_CommandStateSet:OMX_StateIdle", __func__);
        return;
    }

    if (!FillAllTheBuffer()) {
        HDF_LOGE("%{public}s FillAllTheBuffer error", __func__);
        return;
    }

    auto t1 = std::chrono::system_clock::now();
    bool eosFlag = false;
    while (!eosFlag) {
        HDF_LOGI(" inputput run");
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
        const char *sharedAddr = static_cast<const char *>(bufferInfo->avSharedPtr->ReadFromAshmem(0, 0));
        eosFlag = reader_->ReadOnePacket(ioIn_, const_cast<char *>(sharedAddr), bufferInfo->omxBuffer->filledLen);
        bufferInfo->omxBuffer->offset = 0;
        if (eosFlag) {
            bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
        }
        err = client_->EmptyThisBuffer(client_, bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    // wait
    while (!this->exit_) {
        usleep(10000);  // 10000: sleep time 10ms
    }
    auto t2 = std::chrono::system_clock::now();
    std::chrono::duration<double> diff = t2 - t1;
    HDF_LOGI("decoder costtime %{public}f, count=%{public}d", diff.count(), count_);
    // command to IDLE
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    return;
}
int32_t CodecHdiDecode::OnEvent(struct CodecCallbackType *self, OMX_EVENTTYPE event, struct EventInfo *info)
{
    HDF_LOGI("%{public}s: appData[%{public}" PRId64 "] eEvent [%{public}d], nData1[%{public}d]", __func__,
             info->appData, event, info->data1);
    if (event == OMX_EventCmdComplete) {
        OMX_COMMANDTYPE cmd = static_cast<OMX_COMMANDTYPE>(info->data1);
        if (OMX_CommandStateSet == cmd) {
            HDF_LOGI("OMX_CommandStateSet reached, status is %{public}d", info->data2);
            g_core->OnStatusChanged();
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::OnEmptyBufferDone(struct CodecCallbackType *self, int64_t appData,
                                          const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("onEmptyBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiDecode::OnFillBufferDone(struct CodecCallbackType *self, int64_t appData,
                                         const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("onFillBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnFillBufferDone(*buffer);
}

int32_t CodecHdiDecode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::OnFillBufferDone(const struct OmxCodecBuffer &buffer)
{
    if (exit_) {
        return HDF_SUCCESS;
    }

    auto iter = omxBuffers_.find(buffer.bufferId);
    if ((iter == omxBuffers_.end()) || (iter->second == nullptr)) {
        return HDF_SUCCESS;
    }
    count_++;
    // read buffer
    auto bufferInfo = iter->second;
    if (bufferInfo->avSharedPtr != nullptr) {
        void *addr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset));
        ioOut_.write(static_cast<char *>(addr), buffer.filledLen);
    } else if (bufferInfo->bufferHandle != nullptr && buffer_ != nullptr) {
        buffer_->Mmap(*bufferInfo->bufferHandle);
        ioOut_.write(static_cast<char *>(bufferInfo->bufferHandle->virAddr), bufferInfo->bufferHandle->size);
        buffer_->Unmap(*bufferInfo->bufferHandle);
    }

    ioOut_.flush();
    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
        // end
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }
    // call fillthisbuffer again
    auto err = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s FillThisBuffer error", __func__);
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

int main(int argc, char *argv[])
{
    CommandOpt opt;
    CommandParse parse;
    if (!parse.Parse(argc, argv, opt)) {
        return HDF_FAILURE;
    }
    if (g_core == nullptr) {
        g_core = new CodecHdiDecode();
    }
    // Init width, height, input file
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