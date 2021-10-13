/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file video_key_info.h
 *
 * @brief 声明录像关键信息键值对
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef VIDEO_KEY_INFO_H
#define VIDEO_KEY_INFO_H

#include <string>

namespace OHOS::Camera {
/**
 * @brief 数据长度，值类型为int32_t。
 */
const std::string dataSize = "dataSize";

/**
 * @brief 时间戳，单位为纳秒，值类型为int64_t。
 */
const std::string timeStamp = "timeStamp";

/**
 * @brief 是否关键帧，值类型为int32_t，值为1表示当前帧是关键否，值为0表示当前帧不是关键帧。
 */
const std::string isKeyFrame = "isKeyFrame";
} // end namespace OHOS::Camera
#endif