/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "scale_node.h"
#include <securec.h>
#include <fcntl.h>
#include "camera_dump.h"

extern "C" {
#include <jpeglib.h>
#include <transupp.h>
#include "libavutil/frame.h"
#include "libavcodec/avcodec.h"
#include "libswscale/swscale.h"
#include "libavutil/imgutils.h"
}

namespace OHOS::Camera {
const unsigned long long TIME_CONVERSION_NS_S = 1000000000ULL; /* ns to s */

ScaleNode::ScaleNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
}

ScaleNode::~ScaleNode()
{
    CAMERA_LOGI("~ScaleNode Node exit.");
}

RetCode ScaleNode::Start(const int32_t streamId)
{
    CAMERA_LOGI("ScaleNode::Start streamId = %{public}d\n", streamId);
    uint64_t bufferPoolId = 0;
    
    std::vector<std::shared_ptr<IPort>> outPutPortsVector = GetOutPorts();
    for (auto& out : outPutPortsVector) {
        bufferPoolId = out->format_.bufferPoolId_;
    }

    BufferManager* bufferManager = Camera::BufferManager::GetInstance();
    if (bufferManager == nullptr) {
        CAMERA_LOGE("scale buffer get instance failed");
        return RC_ERROR;
    }

    bufferPool_ = bufferManager->GetBufferPool(bufferPoolId);
    if (bufferPool_ == nullptr) {
        CAMERA_LOGE("get bufferpool failed: %{public}zu", bufferPoolId);
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode ScaleNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("ScaleNode::Stop streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode ScaleNode::Flush(const int32_t streamId)
{
    CAMERA_LOGI("ScaleNode::Flush streamId = %{public}d\n", streamId);
    return RC_OK;
}

void ScaleNode::PreviewScaleConver(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("ScaleNode::PreviewScaleConver buffer == nullptr");
        return;
    }

    AVFrame *pFrameRGBA = nullptr;
    AVFrame *pFrameYUV = nullptr;

    uint8_t* temp = (uint8_t*)buffer->GetVirAddress();
    std::map<int32_t, uint8_t*> sizeVirMap = bufferPool_->getSFBuffer(buffer->GetIndex());
    if (sizeVirMap.empty()) {
        return;
    }
    pFrameYUV = av_frame_alloc();
    pFrameRGBA = av_frame_alloc();
    uint8_t* virBUffer = sizeVirMap.begin()->second;
    int32_t virSize = sizeVirMap.begin()->first;
    buffer->SetVirAddress(virBUffer);
    buffer->SetSize(virSize);

    /*avpicture_fill((AVPicture *)pFrameYUV, temp, AV_PIX_FMT_YUYV422, wide_, high_);
    avpicture_fill((AVPicture *)pFrameRGBA, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUYV422,
                   buffer->GetWidth(), buffer->GetHeight());*/
    av_image_fill_arrays(pFrameYUV->data, pFrameYUV->linesize, temp, AV_PIX_FMT_YUYV422, wide_, high_, 1);
    av_image_fill_arrays(pFrameRGBA->data, pFrameRGBA->linesize, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUYV422,
                   buffer->GetWidth(), buffer->GetHeight(), 1);

    struct SwsContext* imgCtx = sws_getContext(wide_, high_, AV_PIX_FMT_YUYV422, buffer->GetWidth(),
                                               buffer->GetHeight(), AV_PIX_FMT_YUYV422, SWS_BILINEAR, 0, 0, 0);

    if (imgCtx != nullptr) {
        sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, high_,
                  pFrameRGBA->data, pFrameRGBA->linesize);
        if (imgCtx) {
            sws_freeContext(imgCtx);
            imgCtx = nullptr;
        }
    } else {
        sws_freeContext(imgCtx);
        imgCtx = nullptr;
    }
    av_frame_free(&pFrameYUV);
    av_frame_free(&pFrameRGBA);
}

void ScaleNode::ScaleConver(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("ScaleNode::ScaleConver buffer == nullptr");
        return;
    }

    AVFrame *pFrameRGBA = nullptr;
    AVFrame *pFrameYUV = nullptr;

    std::map<int32_t, uint8_t*> sizeVirMap = bufferPool_->getSFBuffer(bufferPool_->GetForkBufferId());
    if (sizeVirMap.empty()) {
        CAMERA_LOGE("ScaleNode::ScaleConver sizeVirMap buffer == nullptr");
        return;
    }
    pFrameYUV = av_frame_alloc();
    pFrameRGBA = av_frame_alloc();
    uint8_t* temp = sizeVirMap.begin()->second;

    /*avpicture_fill((AVPicture *)pFrameYUV, temp, AV_PIX_FMT_YUYV422, wide_, high_);
    avpicture_fill((AVPicture *)pFrameRGBA, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUYV422,
                   buffer->GetWidth(), buffer->GetHeight());*/
    av_image_fill_arrays(pFrameYUV->data, pFrameYUV->linesize, temp, AV_PIX_FMT_YUYV422, wide_, high_, 1);
    av_image_fill_arrays(pFrameRGBA->data, pFrameRGBA->linesize, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUYV422,
                   buffer->GetWidth(), buffer->GetHeight(), 1);
    struct SwsContext* imgCtx = sws_getContext(wide_, high_, AV_PIX_FMT_YUYV422, buffer->GetWidth(),
                                               buffer->GetHeight(), AV_PIX_FMT_YUYV422, SWS_BILINEAR, 0, 0, 0);

    if (imgCtx != nullptr) {
        sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, high_,
                  pFrameRGBA->data, pFrameRGBA->linesize);
        if (imgCtx) {
            sws_freeContext(imgCtx);
            imgCtx = nullptr;
        }
    } else {
        sws_freeContext(imgCtx);
        imgCtx = nullptr;
    }
    av_frame_free(&pFrameYUV);
    av_frame_free(&pFrameRGBA);
}

void ScaleNode::ScaleConverToYuv420(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("ScaleNode::ScaleConverToYuv420 buffer == nullptr");
        return;
    }

    AVFrame *pFrameRGBA = nullptr;
    AVFrame *pFrameYUV = nullptr;
    pFrameYUV = av_frame_alloc();
    pFrameRGBA = av_frame_alloc();

    std::map<int32_t, uint8_t*> sizeVirMap = bufferPool_->getSFBuffer(bufferPool_->GetForkBufferId());
    if (sizeVirMap.empty()) {
        CAMERA_LOGE("ScaleNode::ScaleConverToYuv420 sizeVirMap buffer == nullptr");
        return;
    }
    uint8_t* temp = sizeVirMap.begin()->second;

    /*avpicture_fill((AVPicture *)pFrameYUV, temp, AV_PIX_FMT_YUYV422, wide_, high_);
    avpicture_fill((AVPicture *)pFrameRGBA, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_NV21,
                   buffer->GetWidth(), buffer->GetHeight());*/
    av_image_fill_arrays(pFrameYUV->data, pFrameYUV->linesize, temp, AV_PIX_FMT_YUYV422, wide_, high_, 1);
    av_image_fill_arrays(pFrameRGBA->data, pFrameRGBA->linesize, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_NV21,
                   buffer->GetWidth(), buffer->GetHeight(), 1);
    struct SwsContext* imgCtx = sws_getContext(wide_, high_, AV_PIX_FMT_YUYV422, buffer->GetWidth(),
                                               buffer->GetHeight(), AV_PIX_FMT_NV21, SWS_BILINEAR, 0, 0, 0);

    if (imgCtx != nullptr) {
        sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, high_,
                  pFrameRGBA->data, pFrameRGBA->linesize);
        if (imgCtx) {
            sws_freeContext(imgCtx);
            imgCtx = nullptr;
        }
    } else {
        sws_freeContext(imgCtx);
        imgCtx = nullptr;
    }
    av_frame_free(&pFrameYUV);
    av_frame_free(&pFrameRGBA);
    struct timespec ts = {};
    int64_t timestamp = 0;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    timestamp = ts.tv_nsec + ts.tv_sec * TIME_CONVERSION_NS_S;
    buffer->SetEsTimestamp(timestamp);
    buffer->SetEsFrameSize(buffer->GetSize());
    buffer->SetEsKeyFrame(0);
}

void ScaleNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("ScaleNode::DeliverBuffer frameSpec is null");
        return;
    }

    int32_t id = buffer->GetStreamId();
    CAMERA_LOGI("ScaleNode::DeliverBuffer StreamId %{public}d", id);

    if (bufferPool_->GetForkBufferId() != -1) {
        if (buffer->GetEncodeType() == ENCODE_TYPE_JPEG) {
            ScaleConver(buffer);
        } else if (buffer->GetFormat() == CAMERA_FORMAT_YCRCB_420_SP || bufferPool_->GetIsFork() == true) {
            ScaleConverToYuv420(buffer);
        } else {
            PreviewScaleConver(buffer);
        }
    }

    std::vector<std::shared_ptr<IPort>> outPutPorts_;
    outPutPorts_ = GetOutPorts();
    for (auto& it : outPutPorts_) {
        if (it->format_.streamId_ == id) {
            it->DeliverBuffer(buffer);
            CAMERA_LOGI("ScaleNode deliver buffer streamid = %{public}d", it->format_.streamId_);
            return;
        }
    }
}

RetCode ScaleNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("ScaleNode::Capture");
    return RC_OK;
}

RetCode ScaleNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("ScaleNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

REGISTERNODE(ScaleNode, {"Scale"})
} // namespace OHOS::Camera
