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
#ifndef BUFFER_HELPER_H
#define BUFFER_HELPER_H

#include <memory>
#include <base/native_buffer.h>

namespace OHOS::Codec::Omx {
using HDI::Base::NativeBuffer;

class UniqueFd {
public:
    static std::shared_ptr<UniqueFd> Create(int fd, bool transferOwnership);
    ~UniqueFd();
    int Get();

private:
    UniqueFd(int fd);
    int fd_ = -1;
};

sptr<NativeBuffer> ReWrap(const sptr<NativeBuffer>& src, bool isIpcMode);
int32_t Mmap(const sptr<NativeBuffer>& handle);
int32_t Unmap(const sptr<NativeBuffer>& handle);

}
#endif