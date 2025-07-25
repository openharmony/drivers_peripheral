/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_share_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {

sptr<ICodecBuffer> CodecShareBuffer::UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header, bool doCopy)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.fd != nullptr, nullptr, "invalid ashmem fd");
    CODEC_LOGI("port=%{public}u, use ashmem, fd=%{public}d, doCopy=%{public}d",
        portIndex, codecBuffer.fd->Get(), doCopy);

    int size = OHOS::AshmemGetSize(codecBuffer.fd->Get());
    CHECK_AND_RETURN_RET_LOG(size > 0, nullptr, "ashmem fd has invalid size");
    codecBuffer.allocLen = size;

    sptr<Ashmem> shMem = sptr<Ashmem>::MakeSptr(codecBuffer.fd->Release(), size);
    CHECK_AND_RETURN_RET_LOG(shMem != nullptr, nullptr, "create Ashmem failed");

    bool mapd = shMem->MapReadAndWriteAshmem();
    CHECK_AND_RETURN_RET_LOG(mapd, nullptr, "MapReadAndWriteAshmem failed");

    OMX_U8 *va = reinterpret_cast<OMX_U8 *>(const_cast<void*>(shMem->ReadFromAshmem(size, 0)));
    int32_t err = doCopy ? OMX_AllocateBuffer(comp, &header, portIndex, nullptr, size) :
                           OMX_UseBuffer(comp, &header, portIndex, nullptr, size, va);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_AllocateBuffer or OMX_UseBuffer ret = [%{public}x]", err);
        return nullptr;
    }
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd.reset();
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecShareBuffer(
        InitInfo{comp, portIndex, codecBuffer, header}, shMem, doCopy)
    );
}

OHOS::sptr<ICodecBuffer> CodecShareBuffer::AllocateBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.allocLen > 0, nullptr, "invalid allocLen");
    sptr<Ashmem> shMem = Ashmem::CreateAshmem("codechdi", codecBuffer.allocLen);
    CHECK_AND_RETURN_RET_LOG(shMem != nullptr, nullptr, "create Ashmem failed");
    CODEC_LOGI("port=%{public}u, allocate ashmem, fd=%{public}d", portIndex, shMem->GetAshmemFd());

    bool mapd = shMem->MapReadAndWriteAshmem();
    CHECK_AND_RETURN_RET_LOG(mapd, nullptr, "MapReadAndWriteAshmem failed");

    int32_t err = OMX_AllocateBuffer(comp, &header, portIndex, nullptr, codecBuffer.allocLen);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_AllocateBuffer error, err = %{public}x", err);
        return nullptr;
    }
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd = UniqueFd::Create(shMem->GetAshmemFd(), false);
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecShareBuffer(
        InitInfo{comp, portIndex, codecBuffer, header}, shMem, true)
    );
}

int32_t CodecShareBuffer::EmptyThisBuffer(OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer_.allocLen < codecBuffer.offset ||
        codecBuffer_.allocLen < codecBuffer.offset + codecBuffer.filledLen) {
        CODEC_LOGE("invalid param, allocLen %{public}u, offset %{public}u, filledLen %{public}u",
            codecBuffer_.allocLen, codecBuffer.offset, codecBuffer.filledLen);
        return OMX_ErrorBadParameter;
    }
    if (doCopy_) {
        void *src = const_cast<void *>(shMem_->ReadFromAshmem(codecBuffer.filledLen, codecBuffer.offset));
        if (src == nullptr) {
            CODEC_LOGE("invalid param, allocLen %{public}u, offset %{public}u, filledLen %{public}u",
                codecBuffer_.allocLen, codecBuffer.offset, codecBuffer.filledLen);
            return OMX_ErrorBadParameter;
        }
        if (omxBufHeader_->pBuffer == nullptr) {
            CODEC_LOGE("null pBuffer");
            return OMX_ErrorBadParameter;
        }
        auto ret = memcpy_s(omxBufHeader_->pBuffer + codecBuffer.offset, codecBuffer_.allocLen - codecBuffer.offset,
            src, codecBuffer.filledLen);
        if (ret != EOK) {
            CODEC_LOGE("memcpy_s ret [%{public}d]", ret);
            return OMX_ErrorBadParameter;
        }
    }
    return ICodecBuffer::EmptyThisBuffer(codecBuffer);
}

int32_t CodecShareBuffer::FillBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer)
{
    if (codecBuffer_.allocLen < omxBuffer.nOffset ||
        codecBuffer_.allocLen < omxBuffer.nOffset + omxBuffer.nFilledLen) {
        CODEC_LOGE("invalid param, allocLen %{public}u, offset %{public}u, filledLen %{public}u",
            codecBuffer_.allocLen, omxBuffer.nOffset, omxBuffer.nFilledLen);
        return OMX_ErrorBadParameter;
    }
    if (doCopy_) {
        if (omxBuffer.pBuffer == nullptr) {
            CODEC_LOGE("null pBuffer");
            return OMX_ErrorBadParameter;
        }
        if (!shMem_->WriteToAshmem(omxBuffer.pBuffer, omxBuffer.nFilledLen, omxBuffer.nOffset)) {
            CODEC_LOGE("WriteToAshmem failed");
            return OMX_ErrorBadParameter;
        }
    }
    return ICodecBuffer::FillBufferDone(omxBuffer, codecBuffer);
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS