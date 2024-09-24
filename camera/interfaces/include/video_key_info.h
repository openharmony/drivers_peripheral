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
 * @brief Declares the key-value pairs used to record key information of a video frame.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef VIDEO_KEY_INFO_H
#define VIDEO_KEY_INFO_H

#include <string>

namespace OHOS::Camera {
/**
 * @brief Indicates the data length. The value type is int32_t.
 */
const std::string dataSize = "dataSize";
const std::string dataWidth = "dataWidth";
const std::string dataHeight = "dataHeight";
const int32_t VIDEO_KEY_INFO_DATA_SIZE = 0x01;

/**
 * @brief Indicates the timestamp, in nanoseconds. The value type is int64_t.
 */
const std::string timeStamp = "timeStamp";
const int32_t VIDEO_KEY_INFO_TIMESTAMP = 0x02;

/**
 * @brief Specifies whether the frame is a key frame.
 * The value type is int32_t. The value <b>1</b> means that the frame is a key frame, and <b>0</b> means the opposite.
 */
const std::string isKeyFrame = "isKeyFrame";
const int32_t VIDEO_KEY_INFO_IS_KEY_FRAME = 0x03;

/**
 * @brief Indicates the stream id corresponding to the image data. The value type is int32_t.
 */
const std::string streamId = "streamId";
const int32_t VIDEO_KEY_STREAM_ID = 0x04;

/**
 * @brief Indicates the capture id corresponding to the image data. The value type is int32_t.
 */
const std::string captureId = "captureId";
const int32_t VIDEO_KEY_CAPTRUE_ID = 0x05;

/**
 * @brief Specifies whether the image is a degraded image. The value type is int32_t.
 * The value <b>1</b> means that the image is a degraded image, and <b>0</b> means the opposite.
 */
const std::string isDegradedImage = "isDegradedImage";
const int32_t VIDEO_KEY_IS_DEGRADED_IMAGE = 0x06;

/**
 * @brief Indicates the image id corresponding to the image data. The value type is int32_t.
 */
const std::string imageId = "imageId";
const int32_t VIDEO_KEY_IMAGE_ID = 0x07;

/**
 * @brief Indicates the type of to the deferred processing.
 * The value type is int32_t. The value <b>1</b> means that breakgound process, and <b>0</b> means offline process.
 */
const std::string deferredProcessingType = "deferredProcessingType";
const int32_t VIDEO_KEY_DEFERRED_PROCESSING_TYPE = 0x08;

/**
 * @brief Indicates the continuous shooting effect score. The value type is int32_t.
 */
const std::string imageScore = "imageScore";
const int32_t VIDEO_KEY_IMAGE_SCORE = 0x09;

/**
 * @brief Indicates the continuous fromat of image. The value type is int32_t.
 * 0 rgba; 1:jpg; 2:heif
 */
const std::string deferredImageFormat = "deferredImageFormat";
const int32_t VIDEO_KEY_DEFERRED_IMAGE_FORMAT = 0x0A;

/**
 * @brief Indicates the quality level of depth data. The value type is int32_t.
 */
const std::string depthDataQualityLevel = "depthDataQualityLevel";
const int32_t VIDEO_KEY_DEPTH_DATA_QUALITY_LEVEL = 0x0C;

/**
 * @brief Indicates the sequenceId of capture. The value type is int32_t.
 */
const std::string burstSequenceId = "burstSequenceId";
const int32_t VIDEO_KEY_BURST_SEQUENCE_ID = 0x0D;

} // end namespace OHOS::Camera
#endif
