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

#ifndef I_CODEC_BUFFER_H
#define I_CODEC_BUFFER_H
#include <buffer_handle.h>
namespace OHOS {
namespace Codec {
namespace Omx {
 
struct DynamicBuffer {
    int32_t type = 0;
    BufferHandle *bufferHandle = nullptr;
};
 
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
 
#endif // I_CODEC_BUFFER_H