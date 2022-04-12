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

#include <chrono>
#include <dlfcn.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>

#include "codec_hdi_encode.h"

using namespace std;
using namespace OHOS;

#define HDF_LOG_TAG codec_omx_hdi_enc
constexpr int32_t FRAME = 30 << 16;
constexpr int32_t BITRATE = 3000000;
constexpr int32_t PARAM_LEN = 5;
constexpr int32_t FD_SIZE = 4;
constexpr const char *encoder_avc = "OMX.rk.video_encoder.avc";
#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar

constexpr int32_t denominator = 2;
constexpr int32_t numerator = 3;
static CodecHdiEncode *g_core = nullptr;
CodecHdiEncode::CodecHdiEncode() : fpIn_(nullptr), fpOut_(nullptr)
{
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
    exit_ = false;
    isSupply_ = false;
    width_ = 0;
    height_ = 0;
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

void CodecHdiEncode::onStatusChanged()
{
    statusCondition_.notify_one();
}

bool CodecHdiEncode::ReadOneFrame(FILE *fp, char *buf, size_t &filledCount)
{
    bool ret = false;
    filledCount = fread(buf, 1, width_ * height_ * numerator / denominator, fp);
    if (feof(fp)) {
        ret = true;
    }
    return ret;
}

bool CodecHdiEncode::Init(int width, int height, std::string &filename)
{
    this->width_ = width;
    this->height_ = height;
    HDF_LOGI("width[%{public}d], height[%{public}d]", width_, height_);
    fpIn_ = fopen(filename.c_str(), "rb");
    fpOut_ = fopen("/data/out.h264", "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
        HDF_LOGE("failed to open file %{public}s", filename.c_str());
        return false;
    }
    // Interface init
    omxMgr_ = GetCodecComponentManager();
    // init callback object
    callback_ = CodecCallbackTypeStubGetInstance();
    if ((omxMgr_ == nullptr) || (callback_ == nullptr)) {
        return false;
    }
    HDF_LOGI("callback_ [0x%{public}p]", callback_);
    // set the callback
    callback_->EventHandler = &CodecHdiEncode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiEncode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiEncode::OnFillBufferDone;

    // create a component
    auto err = omxMgr_->CreateComponent(&client_, const_cast<char *>(encoder_avc), 0, 0, callback_);
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
    // set input width, height and COLOR, set ouput port width and height
    if (ConfigPortDefine() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigPortDefine error", __func__);
        return false;
    }
    if (ConfigBitMode() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ConfigBitMode error", __func__);
        return false;
    }
    return true;
}

bool CodecHdiEncode::UseBuffers()
{
    // commad to IDLE
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

    // wait executing state
    enum OMX_STATETYPE status;
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
    HDF_LOGI("%{public}s enter, portIndex = %{public}d", __func__, portIndex);
    int bufferSize = 0;
    int bufferCount = 0;
    bool portEnable = false;

    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)portIndex;
    auto err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with OMX_IndexParamPortDefinition : portIndex[%{public}d]",
                 __func__, portIndex);
        return err;
    }

    bufferSize = param.nBufferSize;
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], buffer count [%{public}d], "
             "portEnable[%{public}d], err [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);

    {
        OMX_PARAM_BUFFERSUPPLIERTYPE param;
        InitParam(param);
        param.nPortIndex = (uint32_t)portIndex;
        err = client_->GetParameter(client_, OMX_IndexParamCompBufferSupplier, (int8_t *)&param, sizeof(param));
        HDF_LOGI("param.eBufferSupplier[%{public}d] isSupply [%{public}d], err [%{public}d]", param.eBufferSupplier,
                 this->isSupply_, err);
    }

    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        bufferSize = width_ * height_ * numerator / denominator;
    } else if (bufferSize == 0) {
        bufferSize = width_ * height_;
        HDF_LOGI("bufferSize[%{public}d], width[%{public}d], height[%{public}d]", bufferSize, width_, height_);
    }

    err = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    if (err != HDF_SUCCESS) {
        return err;
    }

    // if port is disable, changed to enable
    if (!portEnable) {
        err = client_->SendCommand(client_, OMX_CommandPortEnable, (uint32_t)portIndex, NULL, 0);
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
        omxBuffer->bufferType = BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = AshmemCreate(0, bufferSize);
        shared_ptr<Ashmem> spSharedMem = make_shared<Ashmem>(fd, bufferSize);
        omxBuffer->bufferLen = FD_SIZE;
        omxBuffer->buffer = (uint8_t *)(unsigned long)fd;
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
        auto err = client_->UseBuffer(client_, (uint32_t)portIndex, omxBuffer.get());
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
void CodecHdiEncode::FreeBuffers()
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
    auto err = client_->GetState(client_, &status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
        return;
    }

    // wait
    if (status != OMX_StateLoaded) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }
}

void CodecHdiEncode::Release()
{
    omxMgr_->DestoryComponent(client_);

    // DestoryComponent has released  client_ and omx component calls DeInit
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
    bool endFlag = false;
    while (!endFlag) {
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
        // read data from ashmem
        void *sharedAddr = (void *)bufferInfo->avSharedPtr->ReadFromAshmem(0, 0);
        endFlag = this->ReadOneFrame(fpIn_, (char *)sharedAddr, bufferInfo->omxBuffer->filledLen);
        HDF_LOGI("read data size is %{public}d", bufferInfo->omxBuffer->filledLen);
        bufferInfo->omxBuffer->offset = 0;
        if (endFlag) {
            bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
        }
        err = client_->EmptyThisBuffer(client_, bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    while (!this->exit_) {
        usleep(10000);
        continue;
    }
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    return;
}

int32_t CodecHdiEncode::OnEvent(struct CodecCallbackType *self, enum OMX_EVENTTYPE event, struct EventInfo *info)
{
    HDF_LOGI("OnEvent: pAppData[0x%{public}p], eEvent [%{public}d], "
             "nData1[%{public}d]",
             info->appData, event, info->data1);
    switch (event) {
        case OMX_EventCmdComplete: {
            OMX_COMMANDTYPE cmd = (OMX_COMMANDTYPE)info->data1;
            if (OMX_CommandStateSet == cmd) {
                HDF_LOGI("OMX_CommandStateSet reached");
                g_core->onStatusChanged();
            }
            break;
        }

        default:
            break;
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::OnEmptyBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                          const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("OnEmptyBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiEncode::OnFillBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                         struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("OnFillBufferDone: pBuffer.bufferID [%{public}d]", buffer->bufferId);
    return g_core->OnFillBufferDone(*buffer);
}

int32_t CodecHdiEncode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    return HDF_SUCCESS;
}

int32_t CodecHdiEncode::OnFillBufferDone(struct OmxCodecBuffer &buffer)
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
    buffer.offset = 0;
    buffer.filledLen = 0;
    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
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
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    auto err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    HDF_LOGI("PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = width_;
    param.format.video.nSliceHeight = height_;
    param.format.video.eColorFormat = AV_COLOR_FORMAT;
    err = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }

    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    err = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    HDF_LOGI("PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = width_;
    param.format.video.nSliceHeight = height_;
    err = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
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
    auto err = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("failed to GetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat");
        return err;
    }
    HDF_LOGI("set Format PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;
    param.eCompressionFormat = OMX_VIDEO_CodingAVC;
    err = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_INPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }

    OMX_VIDEO_PARAM_BITRATETYPE biteType;
    InitParam(biteType);
    biteType.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    err = client_->SetParameter(client_, OMX_IndexParamVideoBitrate, (int8_t *)&biteType, sizeof(biteType));
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s OMX_GetParameter portindex = PORT_INDEX_OUTPUT, err[%{public}d]", __func__, err);
        return err;
    }
    HDF_LOGI("get PORT_INDEX_OUTPUT:OMX_IndexParamVideoBitrate, bit_mode[%{public}d], biterate:[%{publicd}d]",
             biteType.eControlRate, biteType.nTargetBitrate);

    biteType.eControlRate = OMX_Video_ControlRateConstant;
    biteType.nTargetBitrate = BITRATE;
    err = client_->SetParameter(client_, OMX_IndexParamVideoBitrate, (int8_t *)&biteType, sizeof(biteType));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SetParameter with PORT_INDEX_OUTPUT, index is OMX_IndexParamVideoPortFormat",
                 __func__);
        return err;
    }
    return HDF_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc < PARAM_LEN) {
        HDF_LOGE("usage AVC width heigh filename");
        return 0;
    }
    int width = atoi(argv[2]);
    int height = atoi(argv[3]);
    string filename = argv[4];

    if (g_core == nullptr) {
        g_core = new CodecHdiEncode();
    }

    if (!g_core->Init(width, height, filename)) {
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