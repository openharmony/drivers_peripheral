/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "buffer_helper.h"
#include <mutex>
#include <unistd.h>
#include "codec_log_wrapper.h"

namespace OHOS::Codec::Omx {

std::shared_ptr<UniqueFd> UniqueFd::Create(int fd, bool transferOwnership)
{
    int finalFd = transferOwnership ? fd : dup(fd);
    if (finalFd < 0) {
        return nullptr;
    }
    return std::shared_ptr<UniqueFd>(new UniqueFd(finalFd));
}

UniqueFd::UniqueFd(int fd) : fd_(fd) {}

UniqueFd::~UniqueFd()
{
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

int UniqueFd::Get()
{
    return fd_;
}

int UniqueFd::Release()
{
    int fd = fd_;
    fd_ = -1;
    return fd;
}

sptr<SurfaceBuffer> ReWrap(const sptr<NativeBuffer>& src)
{
    if (src == nullptr) {
        return nullptr;
    }
    sptr<SurfaceBuffer> buf = SurfaceBuffer::Create();
    if (buf == nullptr) {
        return nullptr;
    }
    BufferHandle* handle = src->Move();
    if (handle == nullptr) {
        return nullptr;
    }
    buf->SetBufferHandle(handle);
    return buf;
}
}