/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include <poll.h>
#include <securec.h>
#include <unistd.h>
#include "codec_jpeg_core.h"
#include "codec_image_log.h"
#include "hdf_base.h"

#define MAX_WAIT_MS 10

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
int CodecJpegCore::fence_ = -1;
OHOS::sptr<V1_0::ICodecImageCallback> CodecJpegCore::callback_ = nullptr;
int32_t CodecJpegCore::OnEvent(int32_t error)
{
    CODEC_LOGI("response decode callback, ret =[%{public}d]", error);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, HDF_ERR_INVALID_PARAM, "callback_ is null");

    if (fence_ >= 0 && error == HDF_SUCCESS) {
        auto ret = SyncWait(fence_);
        if (ret != EOK) {
            CODEC_LOGE("SyncWait ret err [%{public}d]", ret);
        }
    }
    if (fence_ >= 0) {
        close(fence_);
        fence_ = -1;
    }
    (void)callback_->OnImageEvent(error);
    callback_ = nullptr;
    return HDF_SUCCESS;
}

CodecJpegCore::~CodecJpegCore()
{
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
    callback_ = nullptr;
}

CodecJpegCore::CodecJpegCore()
{
    vdiCallback_ = {&CodecJpegCore::OnEvent};
}

void CodecJpegCore::AddVendorLib()
{
    CODEC_LOGI("start load dependency library!");
    std::string libName = HDF_LIBRARY_FULL_PATH(CODEC_JPEG_VDI_NAME);
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(libName.c_str(), pathBuf) == nullptr) {
        CODEC_LOGE("realpath failed! path = [%{public}s]", pathBuf);
        return;
    }
    libHandle_ = dlopen(pathBuf, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        CODEC_LOGE("Failed to dlopen %{public}s.", libName.c_str());
        return;
    }

    getCodecJpegHwi_= reinterpret_cast<GetCodecJpegHwi>(dlsym(libHandle_, "GetCodecJpegHwi"));
    if (getCodecJpegHwi_ == NULL) {
        CODEC_LOGE("Failed to dlsym GetCodecJpegHwi");
        return;
    }

    JpegHwi_ =  getCodecJpegHwi_();
    if (JpegHwi_ == nullptr) {
        CODEC_LOGE("load dependency library error!");
        return;
    }
    CODEC_LOGI("load dependency library success!");
}

int32_t CodecJpegCore::Init()
{
    if (JpegHwi_ == nullptr) {
        AddVendorLib();
    }
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->JpegInit)();
}

int32_t CodecJpegCore::DeInit()
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->JpegDeInit)();
}

int32_t CodecJpegCore::AllocateInBuffer(BufferHandle **buffer, uint32_t size)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->AllocateInBuffer)(buffer, size);
}

int32_t CodecJpegCore::FreeInBuffer(BufferHandle *buffer)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->FreeInBuffer)(buffer);
}

int32_t CodecJpegCore::DoDecode(BufferHandle *buffer, BufferHandle *outBuffer,
    const V1_0::CodecJpegDecInfo *decInfo, const OHOS::sptr<V1_0::ICodecImageCallback> callbacks, int fd)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    CodecJpegDecInfo *vdiDecInfo = reinterpret_cast<CodecJpegDecInfo *>(const_cast<V1_0::CodecJpegDecInfo *>(decInfo));

    int32_t ret = (JpegHwi_->DoJpegDecode)(buffer, outBuffer, vdiDecInfo, &vdiCallback_);
    if (ret == HDF_SUCCESS) {
        callback_ = callbacks;
        fence_ = fd;
    }
    return ret;
}

int32_t CodecJpegCore::SyncWait(int fd)
{
    int retCode = -EPERM;
    struct pollfd pollfds = {0};
    pollfds.fd = fd;
    pollfds.events = POLLIN;

    do {
        retCode = poll(&pollfds, 1, MAX_WAIT_MS);
    } while (retCode == -EPERM && (errno == EINTR || errno == EAGAIN));

    if (retCode == 0) {
        CODEC_LOGE("fenceFd poll wait timeout !");
        retCode = -EPERM;
        errno = ETIME;
    } else if (retCode > 0) {
        if (static_cast<uint32_t>(pollfds.revents) & (POLLERR | POLLNVAL)) {
            retCode = -EPERM;
            errno = EINVAL;
        }
    }
    return retCode < 0 ? -errno : EOK;
}
} // Image
} // Codec
} // HDI
} // OHOS
