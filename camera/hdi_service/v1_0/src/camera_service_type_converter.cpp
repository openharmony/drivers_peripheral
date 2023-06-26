/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_service_type_converter.h"

namespace OHOS::Camera {

void ConvertStreamInfoHdiToVdi(const StreamInfo &src, VdiStreamInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.width_ = src.width_;
    dst.height_ = src.height_;
    dst.format_ = src.format_;
    dst.dataspace_ = src.dataspace_;
    dst.intent_ = static_cast<VdiStreamIntent>(src.intent_);
    dst.tunneledMode_ = src.tunneledMode_;
    dst.bufferQueue_ = src.bufferQueue_;
    dst.minFrameDuration_ = src.minFrameDuration_;
    dst.encodeType_ = static_cast<VdiEncodeType>(src.encodeType_);
}

void ConvertStreamAttributeHdiToVdi(const StreamAttribute &src, VdiStreamAttribute &dst)
{
    dst.streamId_ = src.streamId_;
    dst.width_ = src.width_;
    dst.height_ = src.height_;
    dst.overrideFormat_ = src.overrideFormat_;
    dst.overrideDataspace_ = src.overrideDataspace_;
    dst.producerUsage_ = src.producerUsage_;
    dst.producerBufferCount_ = src.producerBufferCount_;
    dst.maxBatchCaptureCount_ = src.maxBatchCaptureCount_;
    dst.maxCaptureCount_ = src.maxCaptureCount_;
}

void ConvertCaptureInfoHdiToVdi(const CaptureInfo &src, VdiCaptureInfo &dst)
{
    std::vector<int32_t>().swap(dst.streamIds_);
    for (auto streamId : src.streamIds_) {
        dst.streamIds_.push_back(streamId);
    }
    std::vector<uint8_t>().swap(dst.captureSetting_);
    for (auto capSetting : src.captureSetting_) {
        dst.captureSetting_.push_back(capSetting);
    }
    dst.enableShutterCallback_ = src.enableShutterCallback_;
}

void ConvertCaptureEndedInfoHdiToVdi(const CaptureEndedInfo &src, VdiCaptureEndedInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.frameCount_ = src.frameCount_;
}

void ConvertCaptureErrorInfoHdiToVdi(const CaptureErrorInfo &src, VdiCaptureErrorInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.error_ = static_cast<VdiStreamError>(src.error_);
}

void ConvertStreamInfoVdiToHdi(const VdiStreamInfo &src, StreamInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.width_ = src.width_;
    dst.height_ = src.height_;
    dst.format_ = src.format_;
    dst.dataspace_ = src.dataspace_;
    dst.intent_ = static_cast<StreamIntent>(src.intent_);
    dst.tunneledMode_ = src.tunneledMode_;
    dst.bufferQueue_ = src.bufferQueue_;
    dst.minFrameDuration_ = src.minFrameDuration_;
    dst.encodeType_ = static_cast<EncodeType>(src.encodeType_);
}

void ConvertStreamAttributeVdiToHdi(const VdiStreamAttribute &src, StreamAttribute &dst)
{
    dst.streamId_ = src.streamId_;
    dst.width_ = src.width_;
    dst.height_ = src.height_;
    dst.overrideFormat_ = src.overrideFormat_;
    dst.overrideDataspace_ = src.overrideDataspace_;
    dst.producerUsage_ = src.producerUsage_;
    dst.producerBufferCount_ = src.producerBufferCount_;
    dst.maxBatchCaptureCount_ = src.maxBatchCaptureCount_;
    dst.maxCaptureCount_ = src.maxCaptureCount_;
}

void ConvertCaptureInfoVdiToHdi(const VdiCaptureInfo &src, CaptureInfo &dst)
{
    std::vector<int32_t>().swap(dst.streamIds_);
    for (auto streamId : src.streamIds_) {
        dst.streamIds_.push_back(streamId);
    }
    std::vector<uint8_t>().swap(dst.captureSetting_);
    for (auto capSetting : src.captureSetting_) {
        dst.captureSetting_.push_back(capSetting);
    }
    dst.enableShutterCallback_ = src.enableShutterCallback_;
}

void ConvertCaptureEndedInfoVdiToHdi(const VdiCaptureEndedInfo &src, CaptureEndedInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.frameCount_ = src.frameCount_;
}

void ConvertCaptureErrorInfoVdiToHdi(const VdiCaptureErrorInfo &src, CaptureErrorInfo &dst)
{
    dst.streamId_ = src.streamId_;
    dst.error_ = static_cast<StreamError>(src.error_);
}

} // end namespace OHOS::Camera
