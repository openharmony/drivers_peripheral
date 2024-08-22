/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMAGE_COMMON_H
#define IMAGE_COMMON_H
#include "v2_0/codec_image_type.h"
namespace OHOS {
namespace Codec {
namespace Image {
static const int32_t DATA_BUFFERID = 10;
static const int32_t DATA_SIZE = 20;
static const int32_t DATA_VERSION_NVERSION = 30;
static const int32_t DATA_BUFFERTYPE = 40;
static const int32_t DATA_BUFFERLEN = 50;
static const int32_t DATA_ALLOCLEN = 60;
static const int32_t DATA_FILLEDLEN = 70;
static const int32_t DATA_OFFSET = 80;
static const int32_t DATA_FENCEFD = 90;
static const int32_t DATA_TYPE = 100;
static const int32_t DATA_PTS = 200;
static const int32_t DATA_FLAG = 300;
static const int32_t TESTING_APP_DATA = 33;

void FillDataImageBuffer(HDI::Codec::Image::V2_0::CodecImageBuffer &dataFuzz)
{
    dataFuzz.id = DATA_BUFFERID;
    dataFuzz.size = DATA_SIZE;
    dataFuzz.buffer = nullptr;
    dataFuzz.fenceFd = -1;
}
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS
#endif