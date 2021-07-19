/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "camera_capture.h"
#include <iostream>
#include "camera.h"
#include "stream_base.h"
#include "istream_pipeline_core.h"

namespace OHOS::Camera {
CameraCapture::CameraCapture(int captureId, const std::shared_ptr<CaptureInfo> &captureInfo,
    bool isStreaming, const std::weak_ptr<IStreamPipelineCore> &streamPipelineCore)
    : captureId_(captureId),
      captureInfo_(captureInfo),
      isStreaming_(isStreaming),
      isCancel_(false),
      frameCount_(0),
      streamPipelineCore_(streamPipelineCore),
      captureCallback_(nullptr)
{
}

CameraCapture::~CameraCapture()
{
    CAMERA_LOGV("enter");
    frameCount_ = 0;
}

void CameraCapture::AddStream(const std::shared_ptr<StreamBase> &stream)
{
    if (stream == nullptr) {
        CAMERA_LOGE("stream is null. [captureId = %{public}d]", captureId_);
        return;
    }

    if (stream->GetStreamInfo() == nullptr) {
        CAMERA_LOGE("invalid stream info");
        return;
    }

    auto itr = std::find_if(streams_.begin(), streams_.end(),
        [&stream] (const std::shared_ptr<StreamBase> &s) {
        return s->GetStreamInfo()->streamId_ == stream->GetStreamInfo()->streamId_;
    });
    if (itr == streams_.end()) {
        streams_.push_back(stream);
        CAMERA_LOGV("append a new stream id = %d", stream->GetStreamInfo()->streamId_);
    }
}

uint32_t CameraCapture::DeleteStream(int streamId)
{
    CAMERA_LOGV("enter");
    auto itr = std::find_if(streams_.begin(), streams_.end(),
        [&streamId] (const std::shared_ptr<StreamBase> &stream) {
        std::shared_ptr<StreamInfo> streamInfo = stream->GetStreamInfo();
        if (streamInfo != nullptr && streamId == streamInfo->streamId_) {
            return true;
        } else {
            return false;
        }
    });
    if (itr != streams_.end()) {
        streams_.erase(itr);
        CAMERA_LOGV("delete a stream id = %d", streamId);
    }
    return streams_.size();
}

RetCode CameraCapture::Start()
{
    isCancel_ = false;
    std::shared_ptr<IStreamPipelineCore> streamPipelineCore =
        streamPipelineCore_.lock();
    if (streamPipelineCore == nullptr) {
        CAMERA_LOGE("stream pipelineCore is null.");
        return RC_ERROR;
    }

    std::vector<int32_t> streamIds;
    std::vector<int32_t> types;
    for (auto &stream : streams_) {
        std::shared_ptr<StreamInfo> streamInfo = stream->GetStreamInfo();
        if (streamInfo != nullptr) {
            types.push_back(streamInfo->intent_);
            streamIds.push_back(streamInfo->streamId_);
        }
    }

    RetCode rc = streamPipelineCore->Start(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("start streaming failed. [captureId = %{public}d]", captureId_);
        return RC_ERROR;
    }
    CAMERA_LOGV("pipeline start success");

    rc = streamPipelineCore->Config(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("config stream failed. [captureId = %{public}d]", captureId_);
        return RC_ERROR;
    }
    streamPipelineCore->Capture(streamIds, types, captureId_);

    CAMERA_LOGV("success");
    return RC_OK;
}

RetCode CameraCapture::Cancel()
{
    /* 1. stop stream request buffer in this capture.
     * 2. all resulted buffers are set to error.
     * 3 .record the number of buffers issued. When the waiting count is 0, cancel ends.
     */
    isCancel_ = true;
    // 调用streamCancel，等待所有buffer回上来
    for (auto &stream : streams_) {
        if (stream == nullptr) {
            continue;
        }
        auto info = stream->GetStreamInfo();
        if (info == nullptr) {
            continue;
        }
        CAMERA_LOGD("stop stream [id = %{public}d] begin", info->streamId_);
        stream->Stop();
        CAMERA_LOGD("stop stream [id = %{public}d] end", info->streamId_);
    }
    return RC_OK;
}

void CameraCapture::RequestBuffer()
{
    if (isCancel_) {
        return;
    }
    std::vector<int> reqStreamIds;
    for (auto &stream : streams_) {
        if (stream != nullptr) {
            RetCode rc = stream->Request();
            if (rc != RC_OK) {
                continue;
            }
            std::shared_ptr<StreamInfo> streamInfo = stream->GetStreamInfo();
            if (streamInfo == nullptr) {
                continue;
            }
            reqStreamIds.push_back(streamInfo->streamId_);
        }
    }

    if (captureCallback_ != nullptr && captureCallback_->OnCaptureStarted != nullptr) {
        captureCallback_->OnCaptureStarted(captureId_, reqStreamIds);
    }
}

void CameraCapture::ResultBuffer(int streamId, const std::shared_ptr<IBuffer> &buffer)
{
    RetCode rc = StreamResult(streamId, buffer);
    if (rc != RC_OK) {
        return;
    }

    // save stream resulted frame count
    SaveResultCount(streamId);

    // frame shutter
    FrameShutter();

    // callback capture end
    CaptureEnd();
}

RetCode CameraCapture::StreamResult(int streamId, const std::shared_ptr<IBuffer> &buffer)
{
    CAMERA_LOGV("enter");
    // find stream in this capture
    auto streamItr = std::find_if(streams_.begin(), streams_.end(),
        [streamId](const std::shared_ptr<StreamBase> &stream) {
        if (stream == nullptr) {
            return false;
        }
        std::shared_ptr<StreamInfo> streamInfo = stream->GetStreamInfo();
        if (streamInfo != nullptr && streamId == streamInfo->streamId_) {
            return true;
        } else {
            return false;
        }
    });
    if (streamItr == streams_.end() || (*streamItr) == nullptr) {
        CAMERA_LOGE("streamId is not found. [streamId = %{public}d]", streamId);
        return RC_ERROR;
    }

    // policy stream buffer operation type
    OperationType optType = PolicyBufferOptType(streamId, buffer);
    RetCode rc = (*streamItr)->Result(buffer, optType);
    if (rc != RC_OK) {
        CAMERA_LOGE("stream result buffer failed. [streamId = %{public}d]", streamId);
        return RC_ERROR;
    }

    if (optType == STREAM_BUFFER_ERROR) {
        StreamBufferError(streamId, buffer);
    }

    return RC_OK;
}

OperationType CameraCapture::PolicyBufferOptType(int streamId, const std::shared_ptr<IBuffer> &buffer)
{
    if (isCancel_) {
        return STREAM_BUFFER_CANCEL;
    }

    if (isStreaming_) {
        return STREAM_BUFFER_FLUSH;
    }

    auto itr = streamFrameMap_.find(streamId);
    if (itr != streamFrameMap_.end()) {
        return STREAM_BUFFER_CANCEL;
    } else {
        return STREAM_BUFFER_FLUSH;
    }

    // 判断buffer错误标志位
}

void CameraCapture::SaveResultCount(int streamId)
{
    auto frameItr = streamFrameMap_.find(streamId);
    if (frameItr == streamFrameMap_.end()) {
        streamFrameMap_.insert(std::make_pair(streamId, 1));
    } else {
        frameItr->second++;
    }
}

void CameraCapture::FrameShutter()
{
    if (streamFrameMap_.size() != streams_.size()) {
        return;
    }

    if (captureInfo_ == nullptr || !captureInfo_->enableShutterCallback_) {
        CAMERA_LOGV("frame shutter disabled");
        return;
    }

    if (captureCallback_ == nullptr ||
        captureCallback_->OnFrameShutter == nullptr) {
        CAMERA_LOGE("frame shutter callback is null, skip.");
        return;
    }

    std::vector<int> streamIds;
    std::shared_ptr<StreamInfo> streamInfo = nullptr;
    for (auto &stream : streams_) {
        if (stream == nullptr) {
            continue;
        }
        streamInfo = stream->GetStreamInfo();
        if (streamInfo == nullptr) {
            continue;
        }
        auto itr = streamFrameMap_.find(streamInfo->streamId_);
        if (itr != streamFrameMap_.end()) {
            streamIds.push_back(streamInfo->streamId_);
        }
    }

    if (!streamIds.empty()) {
        captureCallback_->OnFrameShutter(captureId_, streamIds);
    }
}

void CameraCapture::CaptureEnd()
{
    if (isStreaming_) {
        return;
    }
    if (streamFrameMap_.size() == streams_.size()) {
        if (captureCallback_ != nullptr && captureCallback_->OnCaptureEnded != nullptr) {
            std::vector<std::shared_ptr<CaptureEndedInfo>> infos;
            for (auto &framePair : streamFrameMap_) {
                std::shared_ptr<CaptureEndedInfo> info = std::make_shared<CaptureEndedInfo>();
                info->streamId_ = framePair.first;
                info->frameCount_ = static_cast<int>(framePair.second);
                infos.push_back(info);
            }
            captureCallback_->OnCaptureEnded(captureId_, infos);
        }
        std::map<int, uint64_t>().swap(streamFrameMap_);
    }
}

void CameraCapture::StreamBufferError(int streamId, const std::shared_ptr<IBuffer> &buffer)
{
    auto itr = streamErrorMap_.find(streamId);
    if (itr == streamErrorMap_.end()) {
        StreamError err = UNKNOWN_ERROR;
        streamErrorMap_.insert(std::make_pair(streamId, err));
    }

    if (streamFrameMap_.size() == streams_.size()) {
        if (captureCallback_ != nullptr && captureCallback_->OnCaptureError != nullptr) {
            std::vector<std::shared_ptr<CaptureErrorInfo>> errInfos;
            for (auto &errPair : streamErrorMap_) {
                std::shared_ptr<CaptureErrorInfo> errInfo = std::make_shared<CaptureErrorInfo>();
                errInfo->streamId_ = errPair.first;
                errInfo->error_ = errPair.second;
                errInfos.push_back(errInfo);
            }
            captureCallback_->OnCaptureError(captureId_, errInfos);
            std::map<int, StreamError>().swap(streamErrorMap_);
        }
    }
}

std::shared_ptr<CaptureInfo> CameraCapture::GetCaptureInfo() const
{
    return captureInfo_;
}

void CameraCapture::SetCaptureCallback(const std::shared_ptr<CaptureCallback> &callback)
{
    captureCallback_ = callback;
}
}
