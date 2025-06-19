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

#include "codec_hdi_decode.h"
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
using namespace OHOS::HDI::Codec::V4_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
#define HDF_LOG_TAG     codec_omx_hdi_dec
#define AV_COLOR_FORMAT OMX_COLOR_FormatYUV420SemiPlanar
IDisplayBuffer *CodecHdiDecode::gralloc_ = nullptr;
CodecUtil *CodecHdiDecode::util_;
namespace {
constexpr int32_t FRAME = 30 << 16;
constexpr int32_t DENOMINATOR = 2;
constexpr int32_t NUMERATOR = 3;
constexpr int32_t START_CODE_OFFSET_ONE = -1;
constexpr int32_t INIT_BUFFER_CODE = -1;
constexpr int32_t START_CODE_OFFSET_SEC = -2;
constexpr int32_t START_CODE_OFFSET_THIRD = -3;
constexpr int32_t START_CODE_SIZE_FRAME = 4;
constexpr int32_t START_CODE_SIZE_SLICE = 3;
constexpr char START_CODE = 0x1;
}  // namespace

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
    useDMABuffer_ = false;
    componentId_ = 0;
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

void CodecHdiDecode::OnStatusChanged()
{
    statusCondition_.notify_one();
}

int CodecHdiDecode::GetYuvSize()
{
    return width_ * height_ * NUMERATOR / DENOMINATOR;
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
        (void)fread(temp, 1, 1, fp);
        if (*temp != START_CODE) {
            temp++;
            continue;
        }
        // check start code
        if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0) &&
            (temp[START_CODE_OFFSET_THIRD] == 0)) {
            fseek(fp, -START_CODE_SIZE_FRAME, SEEK_CUR);
            temp -= (START_CODE_SIZE_FRAME - 1);
            ret = false;
            break;
            }
        if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0)) {
            fseek(fp, -START_CODE_SIZE_SLICE, SEEK_CUR);
            temp -= (START_CODE_SIZE_SLICE - 1);
            ret = false;
            break;
        }
        temp++;
    }
    filledCount = (temp - buf);
    return ret;
}

bool CodecHdiDecode::Init(const CommandOpt &opt)
{
    this->width_ = opt.width;
    this->height_ = opt.height;
    this->codecMime_ = opt.codec;
    this->stride_ = AlignUp(opt.width);
    this->useBufferHandle_ = opt.useBufferHandle;
    this->useDMABuffer_ = opt.useDMABuffer;
    gralloc_ = IDisplayBuffer::Get();
    fpIn_ = fopen(opt.fileInput.c_str(), "rb");
    fpOut_ = fopen(opt.fileOutput.c_str(), "wb+");
    if ((fpIn_ == nullptr) || (fpOut_ == nullptr)) {
        HDF_LOGE("%{public}s failed to open file", __func__);
        return false;
    }
    omxMgr_ = ICodecComponentManager::Get(false);
    if ((omxMgr_ == nullptr)) {
        HDF_LOGE("%{public}s omxMgr_ is null", __func__);
        return false;
    }
    callback_ = new CodecHdiCallback(shared_from_this());
    if ((callback_ == nullptr)) {
        HDF_LOGE("%{public}s callback_ is null", __func__);
        return false;
    }
    std::string compName("");
    int32_t err = GetComponentName(compName);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetComponentName err", __func__);
        return false;
    }
    err = omxMgr_->CreateComponent(client_, componentId_, compName, reinterpret_cast<int64_t>(this), callback_);
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
    err = client_->GetComponentVersion(verInfo);
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);

    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  PortIndex::PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition", __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("PortIndex::PORT_INDEX_INPUT: eCompressionFormat = %{public}d, eColorFormat = %{public}d ",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    util_->setParmValue(param, width_, height_, stride_);
    util_->ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamPortDefinition, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT, index is OMX_IndexParamPortDefinition", __func__);
        return err;
    }

    // set width, height and color format on output port
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    util_->ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamPortDefinition, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_OUTPUT, index is OMX_IndexParamPortDefinition",
                 __func__);
        return err;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("PortIndex::PORT_INDEX_OUTPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.format.video.eCompressionFormat, param.format.video.eColorFormat);
    util_->setParmValue(param, width_, height_, stride_);
    param.format.video.eColorFormat = AV_COLOR_FORMAT;  // YUV420SP
    util_->ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamPortDefinition, inVec);
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return false;
    }
    param.nPortIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamVideoPortFormat, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed with PortIndex::PORT_INDEX_INPUT", __func__);
        return false;
    }
    util_->VectorToObject(outVec, param);

    HDF_LOGI("set Format PortIndex::PORT_INDEX_INPUT eCompressionFormat = %{public}d, eColorFormat=%{public}d",
             param.eCompressionFormat, param.eColorFormat);
    param.xFramerate = FRAME;  // 30fps,Q16 format
    if (codecMime_ == codecMime::AVC) {
        param.eCompressionFormat = OMX_VIDEO_CodingAVC;  // H264
    } else {
        param.eCompressionFormat = static_cast<OMX_VIDEO_CODINGTYPE>(CODEC_OMX_VIDEO_CodingHEVC);  // H265
    }

    util_->ObjectToVector(param, inVec);
    err = client_->SetParameter(OMX_IndexParamVideoPortFormat, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with PortIndex::PORT_INDEX_INPUT", __func__);
        return false;
    }

    err = CheckAndUseBufferHandle();
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with CheckAndUseBufferHandle", __func__);
        return false;
    }

    err = CheckAndUseDMABuffer();
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed  with CheckAndUseDMABuffer", __func__);
        return false;
    }
    return true;
}

int32_t CodecHdiDecode::CheckSupportBufferType(PortIndex portIndex, CodecBufferType codecBufferType)
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

int32_t CodecHdiDecode::CheckAndUseDMABuffer()
{
    if (!useDMABuffer_) {
        return HDF_SUCCESS;
    }
    return CheckSupportBufferType(PortIndex::PORT_INDEX_INPUT, CODEC_BUFFER_TYPE_DMA_MEM_FD);
}

int32_t CodecHdiDecode::CheckAndUseBufferHandle()
{
    if (!useBufferHandle_) {
        return HDF_SUCCESS;
    }
    SupportBufferType param;
    if (util_->InitParamInOhos(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_INPUT);
    std::vector<int8_t> inVec, outVec;
    util_->ObjectToVector(param, inVec);
    auto err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("OMX_GetParameter OMX_IndexParamSupportBufferType in err [%{public}x]", err);
        return err;
    }
    util_->VectorToObject(outVec, param);

    if (util_->InitParamInOhos(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    util_->ObjectToVector(param, inVec);
    err = client_->GetParameter(OMX_IndexParamSupportBufferType, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("OMX_GetParameter OMX_IndexParamSupportBufferType out err [%{public}x]", err);
        return err;
    }
    util_->VectorToObject(outVec, param);

    GetBufferHandleUsageParams usage;
    if (util_->InitParamInOhos(usage) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    usage.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    util_->ObjectToVector(usage, inVec);
    err = client_->GetParameter(OMX_IndexParamGetBufferHandleUsage, inVec, outVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("OMX_GetParameter OMX_IndexParamGetBufferHandleUsage out err [%{public}x]", err);
        return err;
    }
    util_->VectorToObject(outVec, usage);

    UseBufferType type;
    if (util_->InitParamInOhos(type) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    type.portIndex = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    type.bufferType = CODEC_BUFFER_TYPE_HANDLE;
    util_->ObjectToVector(type, inVec);
    err = client_->SetParameter(OMX_IndexParamUseBufferType, inVec);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("OMX_SetParameter OMX_IndexParamUseBufferType out, err [%{public}x]", err);
        return err;
    }
    return err;
}

bool CodecHdiDecode::UseBuffers()
{
    HDF_LOGI("...command to IDLE....");
    std::vector<int8_t> cmdData;
    auto err = client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with CODEC_COMMAND_STATE_SET:CODEC_STATE_IDLE", __func__);
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

    HDF_LOGI("Wait for CODEC_STATE_IDLE status");
    CodecStateType status = CODEC_STATE_INVALID;
    err = client_->GetState(status);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetState err [%{public}x]", __func__, err);
        return false;
    }
    if (status != CODEC_STATE_IDLE) {
        HDF_LOGI("Wait for CODEC_STATE_LOADED status");
        this->WaitForStatusChanged();
    } else {
        HDF_LOGI(" status is %{public}d", status);
    }

    return true;
}

int32_t CodecHdiDecode::UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize)
{
    if (bufferCount <= 0 || bufferSize <= 0) {
        HDF_LOGE("UseBufferOnPort bufferCount <= 0 or bufferSize <= 0");
        return HDF_ERR_INVALID_PARAM;
    }
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.version.majorVersion = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
        int fd = AshmemCreate(0, bufferSize);
        shared_ptr<Ashmem> sharedMem = make_shared<Ashmem>(fd, bufferSize);
        omxBuffer->fd = fd;
        omxBuffer->bufferhandle = nullptr;
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
        OmxCodecBuffer outBuffer;
        auto err = client_->UseBuffer(static_cast<uint32_t>(portIndex), *omxBuffer.get(), outBuffer);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  portIndex[%{public}d]", __func__, portIndex);
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
            return err;
        }
        omxBuffer->bufferId = outBuffer.bufferId;
        omxBuffer->fd = -1;
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
    if (util_->InitParam(param) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    param.nPortIndex = static_cast<OMX_U32>(portIndex);

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
    HDF_LOGI("buffer index [%{public}d], buffer size [%{public}d], "
             "buffer count [%{public}d], portEnable[%{public}d], ret [%{public}d]",
             portIndex, bufferSize, bufferCount, portEnable, err);
    if (useBufferHandle_ && portIndex == PortIndex::PORT_INDEX_OUTPUT) {
        err = UseBufferHandle(bufferCount, bufferSize);
    } else if (useDMABuffer_ && portIndex == PortIndex::PORT_INDEX_INPUT) {
        err = UseDMABuffer(portIndex, bufferCount, bufferSize);
    } else {
        err = UseBufferOnPort(portIndex, bufferCount, bufferSize);
    }

    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UseBufferOnPort err[%{public}x]", __func__, err);
        return err;
    }
    // set port enable
    if (!portEnable) {
        err = client_->SendCommand(CODEC_COMMAND_PORT_ENABLE, static_cast<uint32_t>(portIndex), {});
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s SendCommand OMX_CommandPortEnable::PortIndex::PORT_INDEX_INPUT error", __func__);
            return err;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::UseDMABuffer(PortIndex portIndex, int bufferCount, int bufferSize)
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
        omxBuffer->type = READ_WRITE_TYPE;

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
        bufferInfo->omxBuffer->fd = outBuffer.fd;
        omxBuffers_.insert(std::make_pair(omxBuffer->bufferId, bufferInfo));
        unUsedInBuffers_.push_back(omxBuffer->bufferId);

        void *addr = mmap(nullptr, static_cast<size_t>(bufferInfo->omxBuffer->allocLen),
                          PROT_READ | PROT_WRITE, MAP_SHARED, bufferInfo->omxBuffer->fd, 0);
        if (addr == nullptr) {
            HDF_LOGE("%{public}s mmap fail fd %{public}d", __func__, omxBuffer->fd);
            return HDF_FAILURE;
        } else {
            addrs_[omxBuffer->bufferId] = addr;
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
                       .usage =  HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};
    for (int i = 0; i < bufferCount; i++) {
        std::shared_ptr<OmxCodecBuffer> omxBuffer = std::make_shared<OmxCodecBuffer>();
        omxBuffer->size = sizeof(OmxCodecBuffer);
        omxBuffer->version.version.majorVersion = 1;
        omxBuffer->bufferType = CODEC_BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle = nullptr;
        int32_t err = gralloc_->AllocMem(alloc, bufferHandle);
        HDF_LOGI("%{public}s AlloceMem ret val ret[%{public}d]", __func__, err);
        if (DISPLAY_SUCCESS != err) {
            HDF_LOGE("%{public}s AllocMem error", __func__);
            return err;
        }
        omxBuffer->fd = -1;
        omxBuffer->allocLen = bufferSize;
        omxBuffer->fenceFd = -1;  // check use -1 first with no window
        omxBuffer->pts = 0;
        omxBuffer->flag = 0;
        omxBuffer->bufferhandle = new NativeBuffer(bufferHandle);
        OmxCodecBuffer outBuffer;
        err = client_->UseBuffer(static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT),
            *omxBuffer.get(), outBuffer);
        omxBuffer->bufferhandle = nullptr;
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to UseBuffer with  output port]", __func__);
            return err;
        }
        omxBuffer->bufferId = outBuffer.bufferId;
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
    (void)client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, {});

    // release all the buffers
    auto iter = omxBuffers_.begin();
    while (iter != omxBuffers_.end()) {
        auto bufferInfo = iter->second;
        iter = omxBuffers_.erase(iter);
        (void)client_->FreeBuffer(static_cast<uint32_t>(bufferInfo->portIndex), *bufferInfo->omxBuffer.get());
        bufferInfo = nullptr;
    }

    unUsedInBuffers_.clear();
    unUsedOutBuffers_.clear();

    CodecStateType status = CODEC_STATE_INVALID;
    int32_t tryCount = 3;
    do {
        int32_t err = client_->GetState(status);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%s GetState error [%{public}x]", __func__, err);
            break;
        }
        if (status != CODEC_STATE_LOADED) {
            HDF_LOGI("Wait for OMX_StateLoaded status");
            this->WaitForStatusChanged();
        }
        tryCount--;
    } while ((status != CODEC_STATE_LOADED) && (tryCount > 0));
}

void CodecHdiDecode::Release()
{
    omxMgr_->DestroyComponent(componentId_);
    client_ = nullptr;
    callback_ = nullptr;
    omxMgr_ = nullptr;
}

bool CodecHdiDecode::FillAllTheBuffer()
{
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("fillThisBUffer, bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter != omxBuffers_.end()) {
            auto bufferInfo = iter->second;
            auto buffer = bufferInfo->omxBuffer.get();
            auto err = client_->FillThisBuffer(*buffer);
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
    if (nSize != 0) {
        bufferID = unUsedInBuffers_.front();
        unUsedInBuffers_.pop_front();
    }
    return bufferID;
}

int32_t CodecHdiDecode::GetComponentName(std::string &compName)
{
    AvCodecRole role = AvCodecRole::MEDIA_ROLETYPE_VIDEO_AVC;
    if (codecMime_ == codecMime::HEVC) {
        role = AvCodecRole::MEDIA_ROLETYPE_VIDEO_HEVC;
    }

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
        if (cap.type == CodecType::VIDEO_DECODER && cap.role == role) {
            compName = cap.compName;
            err = HDF_SUCCESS;
            break;
        }
    }
    return err;
}
void CodecHdiDecode::Run()
{
    HDF_LOGI("...command to CODEC_STATE_EXECUTING....");
    auto err = client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, {});
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to SendCommand with CODEC_COMMAND_STATE_SET:CODEC_STATE_IDLE", __func__);
        return;
    }

    if (!FillAllTheBuffer()) {
        HDF_LOGE("%{public}s FillAllTheBuffer error", __func__);
        return;
    }

    auto t1 = std::chrono::system_clock::now();
    bool eosFlag = false;
    while (!eosFlag) {
        if (this->exit_) {
            break;
        }
        int bufferID = GetFreeBufferId();
        if (bufferID < 0) {
            usleep(10000);  // 10000 for wait 10ms
            continue;
        }
        auto iter = omxBuffers_.find(bufferID);
        if (iter == omxBuffers_.end()) {
            continue;
        }
        auto bufferInfo = iter->second;
        
        if (!FillCodecBuffer(bufferInfo, eosFlag)) {
            break;
        }
        if (eosFlag) {
            bufferInfo->omxBuffer->flag = OMX_BUFFERFLAG_EOS;
        }
        err = client_->EmptyThisBuffer(*bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s EmptyThisBuffer error", __func__);
            return;
        }
    }
    // wait
    while (!this->exit_) {
        usleep(10000);  // 10000 for wait 10ms
    }
    auto t2 = std::chrono::system_clock::now();
    std::chrono::duration<double> diff = t2 - t1;
    HDF_LOGI("cost %{public}f, count=%{public}d", diff.count(), count_);
    (void)client_->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, {});
    return;
}

bool CodecHdiDecode::FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &eosFlag)
{
    if (useDMABuffer_) {
        auto ret = addrs_.find(bufferInfo->omxBuffer->bufferId);
        if (ret != addrs_.end()) {
            eosFlag = this->ReadOnePacket(fpIn_, static_cast<char *>(ret->second), bufferInfo->omxBuffer->filledLen);
            bufferInfo->omxBuffer->offset = 0;
        }
    } else {
        void *sharedAddr = const_cast<void *>(bufferInfo->avSharedPtr->ReadFromAshmem(0, 0));
        eosFlag = this->ReadOnePacket(fpIn_, static_cast<char *>(sharedAddr), bufferInfo->omxBuffer->filledLen);
        bufferInfo->omxBuffer->offset = 0;
    }
    return true;
}

int32_t CodecHdiDecode::OnEmptyBufferDone(const struct OmxCodecBuffer &buffer)
{
    HDF_LOGI("OnEmptyBufferDone, bufferId [%{public}d]", buffer.bufferId);
    unique_lock<mutex> ulk(lockInputBuffers_);
    unUsedInBuffers_.push_back(buffer.bufferId);
    return HDF_SUCCESS;
}

int32_t CodecHdiDecode::OnFillBufferDone(const struct OmxCodecBuffer &buffer)
{
    HDF_LOGI("OnFillBufferDone, bufferId [%{public}d]", buffer.bufferId);
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
        (void)fwrite(bufferInfo->bufferHandle->virAddr, 1, buffer.filledLen, fpOut_);
        gralloc_->Unmap(*bufferInfo->bufferHandle);
    }

    (void)fflush(fpOut_);
    if (buffer.flag == OMX_BUFFERFLAG_EOS) {
        // end
        exit_ = true;
        HDF_LOGI("OnFillBufferDone the END coming");
        return HDF_SUCCESS;
    }
    // call fillthisbuffer again
    auto err = client_->FillThisBuffer(*bufferInfo->omxBuffer.get());
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s FillThisBuffer error", __func__);
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

void CodecHdiDecode::FreeOutBuffer()
{
    uint32_t port = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    for (auto bufferId : unUsedOutBuffers_) {
        HDF_LOGI("FreeOutBuffer, bufferid [%{public}d]", bufferId);
        auto iter = omxBuffers_.find(bufferId);
        if (iter == omxBuffers_.end()) {
            break;
        }
        auto bufferInfo = iter->second;
        auto err = client_->FreeBuffer(port, *bufferInfo->omxBuffer.get());
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s error", __func__);
            return;
        }
        omxBuffers_.erase(iter);
    }
}

void CodecHdiDecode::HandleEventPortSettingsChanged(uint32_t data1, uint32_t data2)
{
    uint32_t port = static_cast<uint32_t>(PortIndex::PORT_INDEX_OUTPUT);
    if (data2 == OMX_IndexParamPortDefinition) {
        auto err = client_->SendCommand(CODEC_COMMAND_PORT_DISABLE, port, {});
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s error", __func__);
            return;
        }
        FreeOutBuffer();
        err = client_->SendCommand(CODEC_COMMAND_PORT_ENABLE, port, {});
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s error", __func__);
            return;
        }
        UseBufferOnPort(PortIndex::PORT_INDEX_OUTPUT);
        FillAllTheBuffer();
    }
}

int32_t CodecHdiDecode::EventHandler(CodecEventType event, const EventInfo &info)
{
    switch (event) {
        case CODEC_EVENT_CMD_COMPLETE: {
            CodecCommandType cmd = (CodecCommandType)info.data1;
            if (CODEC_COMMAND_STATE_SET == cmd) {
                HDF_LOGI("CODEC_COMMAND_STATE_SET reached, status is %{public}d", info.data2);
                this->OnStatusChanged();
            }
            break;
        }
        case OMX_EventPortSettingsChanged: {
            HDF_LOGI("OMX_EventPortSeetingsChanged reached");
            this->HandleEventPortSettingsChanged(info.data1, info.data2);
        }

        default:
            break;
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
    auto core = std::make_shared<CodecHdiDecode>();
    // Init width, height, input file
    if (!core->Init(opt)) {
        return HDF_FAILURE;
    }

    if (!core->Configure()) {
        return HDF_FAILURE;
    }

    if (!core->UseBuffers()) {
        return HDF_FAILURE;
    }

    core->Run();
    core->FreeBuffers();
    core->Release();
    core = nullptr;
}