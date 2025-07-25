/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NODE_UTILS_H__
#include "cstdint"
#include "mutex"
#include "memory"
#include "ibuffer.h"
namespace OHOS::Camera {
    class NodeUtils {
    public:
        struct ImageBufferInfo;
        static int32_t ImageFormatConvert(ImageBufferInfo &srcBufferInfo, ImageBufferInfo &dstBufferInfo);
        static void BufferScaleFormatTransform(std::shared_ptr<IBuffer>& buffer,
            void *dstBuffer = nullptr, uint32_t dstBufferSize = 0);
        static void BufferTransformForStride(std::shared_ptr<IBuffer>& buffer);

        struct ImageBufferInfo {
            int32_t width;
            int32_t height;
            uint32_t format;
            void* bufferAddr;
            uint32_t bufferSize;
        };
    };
};

#define __NODE_UTILS_H__
#endif