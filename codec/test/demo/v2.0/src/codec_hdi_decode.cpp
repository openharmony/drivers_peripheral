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

#include "codec_hdi_decode.h"
#include <chrono>
#include <dlfcn.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>

OHOS::HDI::Display::V1_0::IDisplayGralloc *CodecHdiDecode::gralloc_ = nullptr;
using namespace std;
using namespace OHOS;
constexpr int32_t FD_SIZE = sizeof(int);
constexpr int32_t FRAME = 30 << 16;
constexpr int32_t denominator = 2;
constexpr int32_t numerator = 3;
constexpr int32_t START_CODE_OFFSET_ONE = -1;
constexpr int32_t START_CODE_OFFSET_SEC = -2;
constexpr int32_t START_CODE_OFFSET_THIRD = -3;
constexpr int32_t START_CODE_SIZE_FRAME = 4;
constexpr int32_t START_CODE_SIZE_SLICE = 3;
constexpr char START_CODE = 0x1;
constexpr const char *decoder_avc = "OMX.rk.video_decoder.avc";
constexpr const char *decoder_hevc = "OMX.rk.video_decoder.avc";

#define HDF_LOG_TAG codec_omx_hdi_dec

#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar

static CodecHdiDecode *g_core = nullptr;
CodecHdiDecode::CodecHdiDecode() : fpIn_(nullptr), fpOut_(nullptr)
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    width_ = 0;
    height_ = 0;
    codecMime_ = codecMime::AVC;
    count_ = 0;
    useBufferHandle_ = false;
}

CodecHdiDecode::~CodecHdiDecode()
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

void CodecHdiDecode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiDecode::onStatusChanged()
{
    statusCondition_.notify_one();
}

int CodecHdiDecode::GetYuvSize()
{
    return width_ * height_ * numerator / denominator;
}

bool CodecHdiDecode::ReadOnePacket(FILE *fp, char *buf, uint32_t &filledCount)
{
    // read start code first
    size_t t = fread(buf, 1, START_CODE_SIZE_FRAME, fp);
    if (t < START_CODE_SIZE_FRAME) {
        return true;
    }
    char *temp = buf;
    temp += START_CODE_SIZE_FRAME;
    bool ret = true;
    while (!feof(fp)) {
        t = fread(temp, 1, 1, fp);
        if (*temp == START_CODE) {
            // check start code
            if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0) &&
                (temp[START_CODE_OFFSET_THIRD] == 0)) {
                fseek(fp, -START_CODE_SIZE_FRAME, SEEK_CUR);
                temp -= (START_CODE_SIZE_FRAME - 1);
                ret = false;
                break;
            } else if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0)) {
                fseek(fp, -START_CODE_SIZE_SLICE, SEEK_CUR);
                temp -= (START_CODE_SIZE_SLICE - 1);
                ret = false;
                break;
            }
        }
        temp++;
    }
    filledCount = (temp - buf);
    return ret;
}

bool CodecHdiDecode::Init(CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->codecMime_ = opt.codec;
    this->stride_ = align_up(opt.width);
    this->useBufferHandle_ = opt.useBuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d],stride_[%{public}d],infile[%{public}s],outfile[%{public}s]", width_,
             height_, stride_, opt.fileInput.c_str(), opt.fileOutput.c_str());

    // gralloc init
    gralloc_ = OHOS::HDI::Display::V1_0::IDisplayGralloc::Get();
    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
        HDF_LOGE("%{public}s failed to open file %{public}s or %{public}s", __func__, opt.fileInput.c_str(),
                 opt.fileOutput.c_str());
        return false;
    }

    omxMgr_ = GetCodecComponentManager();

    callback_ = CodecCallbackTypeStubGetInstance();
    if ((omxMgr_ == nullptr) || (callback_ == nullptr)) {
        HDF_LOGE("%{public}s omxMgr_ is null or callback_ is null", __func__);
        return false;
    }

    callback_->EventHandler = &CodecHdiDecode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiDecode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiDecode::OnFillBufferDone;
    int32_t err = HDF_SUCCESS;
    if (codecMime_ == codecMime::AVC) {
        err = omxMgr_->CreateComponent(&client_, const_cast<char *>(decoder_avc), 0, 0, callback_);
    } else {
        err = omxMgr_->CreateComponent(&client_, const_cast<char *>(decoder_hevc), 0, 0, callback_);
    }

    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to CreateComponent", __func__);
        return false;
    }

    struct CompVerInfo verInfo;
    (void)memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
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
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    auto err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
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
    err = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition", __func__);
        return err;
    }

    // set width, height and color format on output port
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
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
    param.format.video.eColorFormat = AV_COLOR_FORMAT;  // YUV420SP
    err = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
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
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    auto err = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT", __func__);
        return false;
    }
    HDF_LOGI("set Format PortIndex::PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;  // 30fps,Q16 format
    if (codecMime_ == codecMime::AVC) {
        param.eCompressionFormat = OMX_VIDEO_CodingAVC;  // H264
    } else {
        param.eCompressionFormat = (OMX_VIDEO_CODINGTYPE)OMX_VIDEO_CodingHEVC;  // H265
    }

    err = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
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
    param.portIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;

    auto err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, (int8_t *)&param, sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:kPortIndexInput, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    InitParamInOhos(param);
    param.portIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    err = client_->GetParameter(client_, OMX_IndexParamSupportBufferType, (int8_t *)&param, sizeof(param));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamSupportBufferType:kPortIndexOutput, err [%{public}x], bufferTypes[%{public}d]",
        err, param.bufferTypes);
    if (err != HDF_SUCCESS) {
        return err;
    }
    GetBufferHandleUsageParams usage;
    InitParamInOhos(usage);
    usage.portIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    err = client_->GetParameter(client_, OMX_IndexParamGetBufferHandleUsage, (int8_t *)&usage, sizeof(usage));
    HDF_LOGI(
        "OMX_GetParameter:OMX_IndexParamGetBufferHandleUsage:kPortIndexOutput, err [%{public}x], usage[%{public}d]",
        err, usage.usage);
    if (err != HDF_SUCCESS) {
        return err;
    }
    UseBufferType type;
    InitParamInOhos(type);
    type.portIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    type.bufferType = BUFFER_TYPE_HANDLE;
    err = client_->SetParameter(client_, OMX_IndexParamUseBufferType, (int8_t *)&type, sizeof(type));
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
    enum OMX_STATETYPE status;
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
        omxBuffer->bufferType = BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = AshmemCreate(0, bufferSize);
        shared_ptr<Ashmem> sharedMem = make_shared<Ashmem>(fd, bufferSize);
        omxBuffer->bufferLen = FD_SIZE;
        omxBuffer->buffer = (uint8_t *)(unsigned long)fd;
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
        auto err = client_->UseBuffer(client_, (uint32_t)portIndex, omxBuffer.get());
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
    int bufferSize = 0;
    int bufferCount = 0;
    bool portEnable = false;

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (OMX_U32)portIndex;
    auto err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }

    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], "
             "buffer count [%{public}d], portEnable[%{public}d], err [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);

    {
        OMX_PARAM_BUFFERSUPPLIERTYPE param;
        InitParam(param);
        param.nPortIndex = (uint32_t)portIndex;
        err = client_->GetParameter(client_, OMX_IndexParamCompBufferSupplier, (int8_t *)&param, sizeof(param));
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
        err = client_->SendCommand(client_, OMX_CommandPortEnable, (uint32_t)portIndex, NULL, 0);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s SendCommand OMX_CommandPortEnable::PortIndex::PORT_INDEX_INPUT error", __func__);
            return err;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::UseBufferHandle(int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0 || gralloc_ == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    AllocInfo alloc = {.width = this->stride_,
                       .height = this->height_,
                       .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};
    int32_t err = HDF_SUCCESS;
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.s.nVersionMajor = 1;
        omxBuffer->bufferType = BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle = nullptr;
        err = gralloc_->AllocMem(alloc, bufferHandle);
        HDF_LOGI("%{public}s AlloceMem ret val err[%{public}d], buffer [%{public}p]", __func__, err, bufferHandle);
        if (DISPLAY_SUCCESS != err) {
            HDF_LOGE("%{public}s AllocMem error", __func__);
            return err;
        }
        size_t handleSize =
            sizeof(BufferHandle) + (sizeof(int32_t) * (bufferHandle->reserveFds + bufferHandle->reserveInts));
        omxBuffer->bufferLen = handleSize;
        omxBuffer->buffer = (uint8_t *)bufferHandle;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;  // check use -1 first with no window
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;
        auto err = client_->UseBuffer(client_, (uint32_t)PortIndex::PORT_INDEX_OUTPUT, omxBuffer.get());
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
        (void)client_->FreeBuffer(client_, (uint32_t)bufferInfo->portIndex, bufferInfo->omxBuffer.get());
        bufferInfo = nullptr;
    }

    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    enum OMX_STATETYPE status;
    auto err = client_->GetState(client_, &status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
        return;
    }
    // wait loaded
    if (status != OMX_StateLoaded) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }
}

void CodecHdiDecode::Release()
{
    omxMgr_->DestoryComponent(client_);
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
                buffer->buffer = (uint8_t *)bufferInfo->bufferHandle;
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
            usleep(10000);
            continue;
        }
        auto iter = omxBuffers_.find(bufferID);
        if (iter == omxBuffers_.end()) {
            continue;
        }
        auto bufferInfo = iter->second;
        void *sharedAddr = (void *)bufferInfo->avSharedPtr->ReadFromAshmem(0, 0);
        eosFlag = this->ReadOnePacket(fpIn_, (char *)sharedAddr, bufferInfo->omxBuffer->filledLen);
        HDF_LOGI("read data size is %{public}d", bufferInfo->omxBuffer->filledLen);
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
        usleep(10000);
        continue;
    }
    auto t2 = std::chrono::system_clock::now();
    std::chrono::duration<double> diff = t2 - t1;
    HDF_LOGI("cost %{public}f, count=%{public}d", diff.count(), count_);
    // command to IDLE
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    return;
}
int32_t CodecHdiDecode::OnEvent(struct CodecCallbackType *self, enum OMX_EVENTTYPE event, struct EventInfo *info)
{
    HDF_LOGI("onEvent: appData[0x%{public}p], eEvent [%{public}d], "
             "nData1[%{public}d]",
             info->appData, event, info->data1);
    switch (event) {
        case OMX_EventCmdComplete: {
            OMX_COMMANDTYPE cmd = (OMX_COMMANDTYPE)info->data1;
            if (OMX_CommandStateSet == cmd) {
                HDF_LOGI("OMX_CommandStateSet reached, status is %{public}d", info->data2);
                g_core->onStatusChanged();
            }
            break;
        }

        default:
            break;
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::OnEmptyBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                          const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("onEmptyBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiDecode::OnFillBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                         struct OmxCodecBuffer *buffer)
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

int32_t CodecHdiDecode::OnFillBufferDone(struct OmxCodecBuffer &buffer)
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
        const void *addr = bufferInfo->avSharedPtr->ReadFromAshmem(buffer.filledLen, buffer.offset);
        (void)fwrite(addr, 1, buffer.filledLen, fpOut_);
    } else if (bufferInfo->bufferHandle != nullptr && gralloc_ != nullptr) {
        gralloc_->Mmap(*bufferInfo->bufferHandle);
        (void)fwrite(bufferInfo->bufferHandle->virAddr, 1,
                     bufferInfo->bufferHandle->width * bufferInfo->bufferHandle->height * numerator / denominator,
                     fpOut_);
        gralloc_->Unmap(*bufferInfo->bufferHandle);
    }

    (void)fflush(fpOut_);
    // reset buffer
    buffer.offset = 0;
    buffer.filledLen = 0;
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