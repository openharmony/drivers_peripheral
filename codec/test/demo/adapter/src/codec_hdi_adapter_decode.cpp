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

#include "codec_hdi_adapter_decode.h"
#include <dlfcn.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>
#include <chrono>
#include <sys/stat.h>
#include "hdi_mpp.h"
#include "codec_type.h"
#include "codec_omx_ext.h"

using namespace std;
using namespace OHOS;
namespace {
    constexpr int32_t FD_SIZE = sizeof(int);
    constexpr int32_t FRAME = (30 << 16);
    constexpr int32_t HEIGHT_OPERATOR = 2;
    constexpr const char *DECODER_AVC = "rk.video_decoder.avc";
    constexpr const char *DECODER_HEVC = "rk.video_decoder.hevc";
    constexpr int32_t START_CODE_OFFSET_ONE = -1;
    constexpr int32_t START_CODE_OFFSET_SEC = -2;
    constexpr int32_t START_CODE_OFFSET_THIRD = -3;
    constexpr int32_t START_CODE_SIZE_FRAME = 4;
    constexpr int32_t START_CODE_SIZE_SLICE = 3;
    constexpr int32_t START_CODE = 1;
    constexpr int32_t USLEEP_TIME = 10000;
}

#define HDF_LOG_TAG codec_omx_hdi_dec

#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar

static CodecHdiAdapterDecode *g_core = nullptr;
CodecHdiAdapterDecode::CodecHdiAdapterDecode() : fpIn_(nullptr), fpOut_(nullptr)
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
    componentId_ = 0;
    inputBufferSize_ = 0;
    needSplit_ = 0;
    srcFileSize_ = 0;
    totalSrcSize_ = 0;
}

CodecHdiAdapterDecode::~CodecHdiAdapterDecode()
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

void CodecHdiAdapterDecode::WaitForStatusChanged()
{
    unique_lock<mutex> autoLock(statusLock_);
    statusCondition_.wait(autoLock);
}

void CodecHdiAdapterDecode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

void CodecHdiAdapterDecode::DumpOutputToFile(FILE *fp, uint8_t *addr)
{
    uint32_t width = width_;
    uint32_t height = height_;
    uint32_t horStride = width_;
    uint32_t verStride = height_;
    uint8_t *base = addr;
    size_t ret = 0;

    // MPP_FMT_YUV420SP
    uint32_t i;
    uint8_t *baseY = base;
    uint8_t *baseC = base + horStride * verStride;

    for (i = 0; i < height; i++, baseY += horStride) {
        ret = fwrite(baseY, 1, width, fp);
        if (ret != width) {
            HDF_LOGE("%{public}s: first fwrite failed", __func__);
            continue;
        }
    }
    for (i = 0; i < height / HEIGHT_OPERATOR; i++, baseC += horStride) {
        ret = fwrite(baseC, 1, width, fp);
        if (ret != width) {
            HDF_LOGE("%{public}s: second fwrite failed", __func__);
            continue;
        }
    }
}

bool CodecHdiAdapterDecode::ReadOnePacket(FILE *fp, uint8_t *buf, uint32_t &filledCount)
{
    filledCount = fread(buf, 1, inputBufferSize_, fp);
    if (filledCount <= 0) {
        return true;
    }
    return false;
}

bool CodecHdiAdapterDecode::ReadOneFrameFromFile(FILE *fp, uint8_t *buf, uint32_t &filledCount)
{
    int32_t readSize = 0;
    // read start code first
    size_t t = fread(buf, 1, START_CODE_SIZE_FRAME, fp);
    if (t < START_CODE_SIZE_FRAME) {
        return true;
    }
    uint8_t *temp = buf;
    temp += START_CODE_SIZE_FRAME;
    while (!feof(fp)) {
        t = fread(temp, 1, 1, fp);
        if (t != 1) {
            continue;
        }

        if (*temp == START_CODE) {
            // check start code
            if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0) &&
                (temp[START_CODE_OFFSET_THIRD] == 0)) {
                fseek(fp, -START_CODE_SIZE_FRAME, SEEK_CUR);
                temp -= (START_CODE_SIZE_FRAME - 1);
                break;
            } else if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0)) {
                fseek(fp, -START_CODE_SIZE_SLICE, SEEK_CUR);
                temp -= (START_CODE_SIZE_SLICE - 1);
                break;
            }
        }
        temp++;
    }
    readSize = (temp - buf);
    filledCount = readSize;
    totalSrcSize_ += readSize;
    return (totalSrcSize_ >= srcFileSize_);
}

bool CodecHdiAdapterDecode::Init(CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->codecMime_ = opt.codec;
    this->stride_ = AlignUp(opt.width);
    this->useBufferHandle_ = opt.useBuffer;
    HDF_LOGI("width[%{public}d], height[%{public}d],stride_[%{public}d],infile[%{public}s],outfile[%{public}s]",
             width_, height_, stride_, opt.fileInput.c_str(), opt.fileOutput.c_str());

    struct stat fileStat = {0};
    stat(opt.fileInput.c_str(), &fileStat);
    srcFileSize_ = fileStat.st_size;
    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
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

    callback_->EventHandler = &CodecHdiAdapterDecode::OnEvent;
    callback_->EmptyBufferDone = &CodecHdiAdapterDecode::OnEmptyBufferDone;
    callback_->FillBufferDone = &CodecHdiAdapterDecode::OnFillBufferDone;
    int32_t ret = HDF_SUCCESS;
    if (codecMime_ == codecMime::AVC) {
        ret = omxMgr_->CreateComponent(
            &client_, &componentId_, const_cast<char *>(DECODER_AVC), (int64_t)this, callback_);
    } else {
        ret = omxMgr_->CreateComponent(
            &client_, &componentId_, const_cast<char *>(DECODER_HEVC), (int64_t)this, callback_);
    }

    if (ret != HDF_SUCCESS || client_ == nullptr) {
        HDF_LOGE("%{public}s errNo[%{public}d] CreateComponent or client is null", __func__, ret);
        return false;
    }

    return true;
}

int32_t CodecHdiAdapterDecode::ConfigMppPassthrough()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    PassthroughParam param;
    memset_s(&param, sizeof(PassthroughParam), 0, sizeof(PassthroughParam));
    CodecType ct = VIDEO_DECODER;
    param.key = KEY_CODEC_TYPE;
    param.val = &ct;
    param.size = sizeof(ct);
    auto ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] key is KEY_CODEC_TYPE", __func__, ret);
        return ret;
    }

    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    param.key = (ParamKey)KEY_EXT_DEFAULT_CFG_RK;
    int32_t needDefault = 1;
    param.val = &needDefault;
    param.size = sizeof(int32_t);
    ret = client_->GetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] key is KEY_EXT_DEFAULT_CFG_RK", __func__, ret);
        return ret;
    }
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    param.key = (ParamKey)KEY_EXT_SPLIT_PARSE_RK;

    needSplit_ = 0;
    param.val = &needSplit_;
    param.size = sizeof(uint32_t);
    ret = client_->SetParameter(client_, OMX_IndexParamPassthrough, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] key is KEY_EXT_SPLIT_PARSE_RK", __func__, ret);
        return ret;
    }
    return ret;
}

int32_t CodecHdiAdapterDecode::ConfigPortDefine()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    // set width, height and color format on output port
    OMX_PARAM_PORTDEFINITIONTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_OUTPUT;
    auto ret = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to GetParameter OMX_IndexParamPortDefinition", __func__, ret);
        return ret;
    }
    HDF_LOGI("get format: eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    param.format.video.nFrameWidth = width_;
    param.format.video.nFrameHeight = height_;
    param.format.video.nStride = stride_;
    param.format.video.nSliceHeight = height_;
    param.format.video.eColorFormat = AV_COLOR_FORMAT;  // YUV420SP
    ret = client_->SetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to SetParameter OMX_IndexParamPortDefinition", __func__, ret);
        return ret;
    }
    return ret;
}

bool CodecHdiAdapterDecode::Configure()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return false;
    }
    if (ConfigMppPassthrough() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error,ConfigMppPassthrough failed", __func__);
        return false;
    }
    if (ConfigPortDefine() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error,ConfigPortDefine failed", __func__);
        return false;
    }

    OMX_VIDEO_PARAM_PORTFORMATTYPE param;
    InitParam(param);
    param.nPortIndex = (uint32_t)PortIndex::PORT_INDEX_INPUT;
    auto ret = client_->GetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to GetParameter OMX_IndexParamVideoPortFormat", __func__, ret);
        return false;
    }
    HDF_LOGI("set Format eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;  // 30fps,Q16 format
    if (codecMime_ == codecMime::AVC) {
        param.eCompressionFormat = OMX_VIDEO_CodingAVC;  // H264
    } else {
        param.eCompressionFormat = (OMX_VIDEO_CODINGTYPE)CODEC_OMX_VIDEO_CodingHEVC;  // H265
    }

    ret = client_->SetParameter(client_, OMX_IndexParamVideoPortFormat, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to SetParameter OMX_IndexParamVideoPortFormat", __func__, ret);
        return false;
    }

    return true;
}

bool CodecHdiAdapterDecode::UseBuffers()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("...command to IDLE....");
    auto ret = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to SendCommand with StateSet:OMX_StateIdle", __func__, ret);
        return false;
    }

    ret = UseBufferOnPort(PortIndex::PORT_INDEX_INPUT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] UseBufferOnPort PortIndex::PORT_INDEX_INPUT", __func__, ret);
        return false;
    }

    ret = UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] UseBufferOnPort PortIndex::PORT_INDEX_OUTPUT", __func__, ret);
        return false;
    }

    HDF_LOGI("Wait for OMX_StateIdle status");
    enum OMX_STATETYPE status;
    ret = client_->GetState(client_, &status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState ret [%{public}x]", __func__, ret);
        return false;
    }
    if (status != OMX_StateIdle) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI("status is %{public}d", status);
    }

    return true;
}

int32_t CodecHdiAdapterDecode::UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (client_ == nullptr || bufferCount <= 0 || bufferSize <= 0) {
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
        auto ret = client_->AllocateBuffer(client_, (uint32_t)portIndex, omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE(
                "%{public}s errNo[%{public}d] to AllocateBuffer with portIndex[%{public}d]", __func__, ret, portIndex);
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
            return ret;
        }
        omxBuffer->bufferLen = 0;

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

int32_t CodecHdiAdapterDecode::UseBufferOnPort(PortIndex portIndex)
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
    param.nPortIndex = (OMX_U32)portIndex;
    auto ret = client_->GetParameter(client_, OMX_IndexParamPortDefinition, (int8_t *)&param, sizeof(param));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] GetParameter with OMX_IndexParamPortDefinition:portIndex[%{public}d]",
                 __func__, ret, portIndex);
        return ret;
    }

    bufferSize = param.nBufferSize;
    if (portIndex == PortIndex::PORT_INDEX_INPUT) {
        inputBufferSize_ = bufferSize;
    }
    bufferCount = param.nBufferCountActual;
    portEnable = param.bEnabled;
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], "
             "buffer count [%{public}d], portEnable[%{public}d], ret [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, ret);

    ret = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort ret[%{public}x]", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

void CodecHdiAdapterDecode::FreeBuffers()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return;
    }
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
    auto ret = client_->GetState(client_, &status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState error [%{public}x]", __func__, ret);
        return;
    }
    // wait loaded
    if (status != OMX_StateLoaded) {
        HDF_LOGI("Wait for OMX_StateLoaded status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI("status is %{public}d", status);
    }
}

void CodecHdiAdapterDecode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    client_ = nullptr;
    CodecComponentManagerRelease();
}

int CodecHdiAdapterDecode::GetFreeBufferId()
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

void CodecHdiAdapterDecode::start()
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return;
    }
    auto ret = client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateExecuting, NULL, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s errNo[%{public}d] to SendCommand with StateSet:OMX_StateIdle", __func__, ret);
        return;
    }
}

void CodecHdiAdapterDecode::Run()
{
    CodecHdiAdapterDecode::start();
    auto t1 = std::chrono::system_clock::now();
    bool eosFlag = false;
    while (!eosFlag) {
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
        void *sharedAddr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(0, 0));
        if (needSplit_ == 1) {
            eosFlag = this->ReadOnePacket(fpIn_, reinterpret_cast<uint8_t *>(sharedAddr),
                bufferInfo->omxBuffer->filledLen);
        } else {
            eosFlag = this->ReadOneFrameFromFile(fpIn_, reinterpret_cast<uint8_t *>(sharedAddr),
                bufferInfo->omxBuffer->filledLen);
        }
        bufferInfo->omxBuffer->offset = 0;
        if (eosFlag) {
            bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
        }
        auto ret = client_->EmptyThisBuffer(client_, bufferInfo->omxBuffer.get());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    // wait
    while (!this->exit_) {
        usleep(USLEEP_TIME);
    }
    auto t2 = std::chrono::system_clock::now();
    std::chrono::duration<double> diff = t2 - t1;
    HDF_LOGI("cost %{public}f, count=%{public}d", diff.count(), count_);
    // command to IDLE
    (void)client_->SendCommand(client_, OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
    return;
}

int32_t CodecHdiAdapterDecode::OnEvent(struct CodecCallbackType *self, OMX_EVENTTYPE event, struct EventInfo *info)
{
    switch (event) {
        case OMX_EventCmdComplete: {
            OMX_COMMANDTYPE cmd = (OMX_COMMANDTYPE)info->data1;
            if (OMX_CommandStateSet == cmd) {
                HDF_LOGI("OMX_CommandStateSet reached, status is %{public}d", info->data2);
                g_core->OnStatusChanged();
            }
            break;
        }

        default:
            break;
    }

    return HDF_SUCCESS;
}

int32_t CodecHdiAdapterDecode::OnEmptyBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    return g_core->OnEmptyBufferDone(*buffer);
}

int32_t CodecHdiAdapterDecode::OnFillBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    return g_core->OnFillBufferDone(*buffer);
}

int32_t CodecHdiAdapterDecode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    return HDF_SUCCESS;
}

int32_t CodecHdiAdapterDecode::OnFillBufferDone(const struct OmxCodecBuffer &buffer)
{
    if (client_ == nullptr) {
        HDF_LOGE("%{public}s error,client_ is null", __func__);
        return HDF_FAILURE;
    }
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
        DumpOutputToFile(fpOut_, reinterpret_cast<uint8_t *>(const_cast<void *>(addr)));
    }

    (void)fflush(fpOut_);
    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
        // end
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }
    // call fillthisbuffer again
    auto ret = client_->FillThisBuffer(client_, bufferInfo->omxBuffer.get());
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s FillThisBuffer error", __func__);
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

int main(int argc, char *argv[])
{
    CommandOpt opt;
    CommandAdapterParse parse;
    if (!parse.Parse(argc, argv, opt)) {
        return HDF_FAILURE;
    }
    if (g_core == nullptr) {
        g_core = new CodecHdiAdapterDecode();
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
