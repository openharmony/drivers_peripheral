/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "codec_node.h"
#include <securec.h>

extern "C" {
#include <jpeglib.h>
#include <transupp.h>
#include "libavutil/frame.h"
#include "libavcodec/avcodec.h"
#include "libswscale/swscale.h"
}

namespace OHOS::Camera {
uint32_t RKCodecNode::previewWidth_ = 640;
uint32_t RKCodecNode::previewHeight_ = 480;
const unsigned long long TIME_CONVERSION_NS_S = 1000000000ULL; /* ns to s */

RKCodecNode::RKCodecNode(const std::string& name, const std::string& type) : NodeBase(name, type)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
    jpegRotation_ = static_cast<uint32_t>(JXFORM_ROT_270);
    jpegQuality_ = 100; // 100:jpeg quality
}

RKCodecNode::~RKCodecNode()
{
    CAMERA_LOGI("~RKCodecNode Node exit.");
}

RetCode RKCodecNode::Start(const int32_t streamId)
{
    CAMERA_LOGI("RKCodecNode::Start streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode RKCodecNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("RKCodecNode::Stop streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode RKCodecNode::Flush(const int32_t streamId)
{
    CAMERA_LOGI("RKCodecNode::Flush streamId = %{public}d\n", streamId);
    return RC_OK;
}

static void RotJpegImg(
    const uint8_t *inputImg, size_t inputSize, uint8_t **outImg, size_t *outSize, JXFORM_CODE rotDegrees)
{
    struct jpeg_decompress_struct inputInfo;
    struct jpeg_error_mgr jerrIn;
    struct jpeg_compress_struct outInfo;
    struct jpeg_error_mgr jerrOut;
    jvirt_barray_ptr *src_coef_arrays;
    jvirt_barray_ptr *dst_coef_arrays;

    inputInfo.err = jpeg_std_error(&jerrIn);
    jpeg_create_decompress(&inputInfo);
    outInfo.err = jpeg_std_error(&jerrOut);
    jpeg_create_compress(&outInfo);
    jpeg_mem_src(&inputInfo, inputImg, inputSize);
    jpeg_mem_dest(&outInfo, outImg, (unsigned long *)outSize);

    JCOPY_OPTION copyoption;
    jpeg_transform_info transformoption;
    transformoption.transform = rotDegrees;
    transformoption.perfect = TRUE;
    transformoption.trim = FALSE;
    transformoption.force_grayscale = FALSE;
    transformoption.crop = FALSE;

    jcopy_markers_setup(&inputInfo, copyoption);
    (void)jpeg_read_header(&inputInfo, TRUE);

    if (!jtransform_request_workspace(&inputInfo, &transformoption)) {
        CAMERA_LOGE("%s: transformation is not perfect", __func__);
        return;
    }

    src_coef_arrays = jpeg_read_coefficients(&inputInfo);
    jpeg_copy_critical_parameters(&inputInfo, &outInfo);
    dst_coef_arrays = jtransform_adjust_parameters(&inputInfo, &outInfo, src_coef_arrays, &transformoption);
    jpeg_write_coefficients(&outInfo, dst_coef_arrays);
    jcopy_markers_execute(&inputInfo, &outInfo, copyoption);
    jtransform_execute_transformation(&inputInfo, &outInfo, src_coef_arrays, &transformoption);

    jpeg_finish_compress(&outInfo);
    jpeg_destroy_compress(&outInfo);
    (void)jpeg_finish_decompress(&inputInfo);
    jpeg_destroy_decompress(&inputInfo);
}

RetCode RKCodecNode::ConfigJpegOrientation(common_metadata_header_t* data)
{
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_JPEG_ORIENTATION, &entry);
    if (ret != 0 || entry.data.i32 == nullptr) {
        CAMERA_LOGI("tag not found");
        return RC_ERROR;
    }

    JXFORM_CODE jxRotation = JXFORM_ROT_270;
    int32_t ohosRotation = *entry.data.i32;
    if (ohosRotation == OHOS_CAMERA_JPEG_ROTATION_0) {
        jxRotation = JXFORM_NONE;
    } else if (ohosRotation == OHOS_CAMERA_JPEG_ROTATION_90) {
        jxRotation = JXFORM_ROT_90;
    } else if (ohosRotation == OHOS_CAMERA_JPEG_ROTATION_180) {
        jxRotation = JXFORM_ROT_180;
    } else {
        jxRotation = JXFORM_ROT_270;
    }
    jpegRotation_ = static_cast<uint32_t>(jxRotation);
    return RC_OK;
}

RetCode RKCodecNode::ConfigJpegQuality(common_metadata_header_t* data)
{
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_JPEG_QUALITY, &entry);
    if (ret != 0) {
        CAMERA_LOGI("tag OHOS_JPEG_QUALITY not found");
        return RC_ERROR;
    }

    const int HIGH_QUALITY_JPEG = 100;
    const int MIDDLE_QUALITY_JPEG = 95;
    const int LOW_QUALITY_JPEG = 85;

    CAMERA_LOGI("OHOS_JPEG_QUALITY is = %{public}d", static_cast<int>(entry.data.u8[0]));
    if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_LOW) {
        jpegQuality_ = LOW_QUALITY_JPEG;
    } else if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_MIDDLE) {
        jpegQuality_ = MIDDLE_QUALITY_JPEG;
    } else if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_HIGH) {
        jpegQuality_ = HIGH_QUALITY_JPEG;
    } else {
        jpegQuality_ = HIGH_QUALITY_JPEG;
    }
    return RC_OK;
}

RetCode RKCodecNode::Config(const int32_t streamId, const CaptureMeta& meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return RC_ERROR;
    }

    common_metadata_header_t* data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return RC_ERROR;
    }

    RetCode rc = ConfigJpegOrientation(data);

    rc = ConfigJpegQuality(data);
    return rc;
}

void RKCodecNode::encodeJpegToMemory(uint8_t* image, int width, int height,
    const char* comment, unsigned long* jpegSize, uint8_t** jpegBuf)
{
    struct jpeg_compress_struct cInfo;
    struct jpeg_error_mgr jErr;
    JSAMPROW row_pointer[1];
    int row_stride = 0;
    constexpr uint32_t colorMap = 3;
    constexpr uint32_t pixelsThick = 3;

    cInfo.err = jpeg_std_error(&jErr);

    jpeg_create_compress(&cInfo);
    cInfo.image_width = width;
    cInfo.image_height = height;
    cInfo.input_components = colorMap;
    cInfo.in_color_space = JCS_RGB;

    jpeg_set_defaults(&cInfo);
    CAMERA_LOGE("RKCodecNode::encodeJpegToMemory jpegQuality_ is = %{public}d", jpegQuality_);
    jpeg_set_quality(&cInfo, jpegQuality_, TRUE);
    jpeg_mem_dest(&cInfo, jpegBuf, jpegSize);
    jpeg_start_compress(&cInfo, TRUE);

    if (comment) {
        jpeg_write_marker(&cInfo, JPEG_COM, (const JOCTET*)comment, strlen(comment));
    }

    row_stride = width;
    while (cInfo.next_scanline < cInfo.image_height) {
        row_pointer[0] = &image[cInfo.next_scanline * row_stride * pixelsThick];
        jpeg_write_scanlines(&cInfo, row_pointer, 1);
    }

    jpeg_finish_compress(&cInfo);
    jpeg_destroy_compress(&cInfo);

    size_t rotJpgSize = 0;
    uint8_t* rotJpgBuf = nullptr;
    /* rotate image */
    RotJpegImg(*jpegBuf, *jpegSize, &rotJpgBuf, &rotJpgSize, static_cast<JXFORM_CODE>(jpegRotation_));
    if (rotJpgBuf != nullptr && rotJpgSize != 0) {
        free(*jpegBuf);
        *jpegBuf = rotJpgBuf;
        *jpegSize = rotJpgSize;
    }
}

void RKCodecNode::Yuv422ToRGBA8888(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToRGBA8888 buffer == nullptr");
        return;
    }

    AVFrame *pFrameRGBA = nullptr;
    AVFrame *pFrameYUV = nullptr;
    pFrameYUV = av_frame_alloc();
    pFrameRGBA = av_frame_alloc();
    previewWidth_ = buffer->GetWidth();
    previewHeight_ = buffer->GetHeight();

    void* temp = malloc(buffer->GetSize());
    if (temp == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToRGBA8888 malloc buffer == nullptr");
        return;
    }
    int ret = memcpy_s((uint8_t *)temp, buffer->GetSize(), (uint8_t *)buffer->GetVirAddress(), buffer->GetSize());
    if (ret == 0) {
        buffer->SetEsFrameSize(buffer->GetSize());
    } else {
        printf("memcpy_s failed!\n");
        buffer->SetEsFrameSize(0);
    }

    avpicture_fill((AVPicture *)pFrameYUV, (uint8_t *)temp, AV_PIX_FMT_YUYV422, previewWidth_, previewHeight_);
    avpicture_fill((AVPicture *)pFrameRGBA, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_RGBA,
                   previewWidth_, previewHeight_);

    struct SwsContext* imgCtx = sws_getContext(previewWidth_, previewHeight_, AV_PIX_FMT_YUYV422, previewWidth_,
                                               previewHeight_, AV_PIX_FMT_RGBA, SWS_BILINEAR, 0, 0, 0);

    if (imgCtx != nullptr) {
        sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, previewHeight_,
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
    free(temp);
}

void RKCodecNode::Yuv422ToYuv420(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToYuv420 buffer == nullptr");
        return;
    }

    AVFrame *pFrameY420 = nullptr;
    AVFrame *pFrameYUV = nullptr;
    pFrameYUV = av_frame_alloc();
    pFrameY420 = av_frame_alloc();

    void* temp = malloc(buffer->GetSize());
    if (temp == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToYuv420 malloc buffer == nullptr");
        return;
    }
    int ret = memcpy_s((uint8_t *)temp, buffer->GetSize(), (uint8_t *)buffer->GetVirAddress(), buffer->GetSize());
    if (ret == 0) {
        buffer->SetEsFrameSize(buffer->GetSize());
    } else {
        printf("memcpy_s failed!\n");
        buffer->SetEsFrameSize(0);
    }

    avpicture_fill((AVPicture *)pFrameYUV, (uint8_t *)temp, AV_PIX_FMT_YUYV422, previewWidth_, previewHeight_);
    avpicture_fill((AVPicture *)pFrameY420, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUV420P,
                   previewWidth_, previewHeight_);

    struct SwsContext* imgCtx = sws_getContext(previewWidth_, previewHeight_, AV_PIX_FMT_YUYV422, previewWidth_,
                                               previewHeight_, AV_PIX_FMT_YUV420P, SWS_BILINEAR, 0, 0, 0);

    if (imgCtx != nullptr) {
        sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, previewHeight_,
                  pFrameY420->data, pFrameY420->linesize);
        if (imgCtx) {
            sws_freeContext(imgCtx);
            imgCtx = nullptr;
        }
    } else {
        sws_freeContext(imgCtx);
        imgCtx = nullptr;
    }
    av_frame_free(&pFrameYUV);
    av_frame_free(&pFrameY420);
    free(temp);
}

void RKCodecNode::Yuv422ToJpeg(std::shared_ptr<IBuffer>& buffer)
{
    constexpr uint32_t RGB24Width = 3;

    if (buffer == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToJpeg buffer == nullptr");
        return;
    }

    uint8_t* jBuf = nullptr;
    unsigned long jpegSize = 0;
    uint32_t tempSize = (previewWidth_ * previewHeight_ * RGB24Width);
    void* temp = malloc(tempSize);
    if (temp == nullptr) {
        CAMERA_LOGI("RKCodecNode::Yuv422ToJpeg malloc buffer == nullptr");
        return;
    }

    AVFrame *m_pFrameRGB = nullptr;
    AVFrame *pFrameYUV = nullptr;
    pFrameYUV = av_frame_alloc();
    m_pFrameRGB = av_frame_alloc();

    avpicture_fill((AVPicture *)pFrameYUV, (uint8_t *)buffer->GetVirAddress(), AV_PIX_FMT_YUYV422,
                   previewWidth_, previewHeight_);
    avpicture_fill((AVPicture *)m_pFrameRGB, (uint8_t *)temp, AV_PIX_FMT_RGB24,
                   previewWidth_, previewHeight_);
    struct SwsContext* imgCtx = sws_getContext(previewWidth_, previewHeight_, AV_PIX_FMT_YUYV422, previewWidth_,
                                               previewHeight_, AV_PIX_FMT_RGB24, SWS_BILINEAR, 0, 0, 0);

    sws_scale(imgCtx, pFrameYUV->data, pFrameYUV->linesize, 0, previewHeight_,
              m_pFrameRGB->data, m_pFrameRGB->linesize);
    sws_freeContext(imgCtx);
    imgCtx = nullptr;
    av_frame_free(&pFrameYUV);
    av_frame_free(&m_pFrameRGB);
    encodeJpegToMemory((uint8_t *)temp, previewWidth_, previewHeight_, nullptr, &jpegSize, &jBuf);

    int ret = memcpy_s((uint8_t*)buffer->GetVirAddress(), buffer->GetSize(), jBuf, jpegSize);
    if (ret == 0) {
        buffer->SetEsFrameSize(jpegSize);
    } else {
        CAMERA_LOGI("memcpy_s failed, ret = %{public}d\n", ret);
        buffer->SetEsFrameSize(0);
    }

    free(jBuf);
    free(temp);
    CAMERA_LOGE("RKCodecNode::Yuv422ToJpeg jpegSize = %{public}d\n", jpegSize);
}

void RKCodecNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("RKCodecNode::DeliverBuffer frameSpec is null");
        return;
    }

    int32_t id = buffer->GetStreamId();
    CAMERA_LOGE("RKCodecNode::DeliverBuffer StreamId %{public}d", id);
    if (buffer->GetEncodeType() == ENCODE_TYPE_JPEG) {
        Yuv422ToJpeg(buffer);
    } else if (buffer->GetEncodeType() == ENCODE_TYPE_H264) {
        Yuv422ToYuv420(buffer);
    } else {
        Yuv422ToRGBA8888(buffer);
    }

    std::vector<std::shared_ptr<IPort>> outPutPorts_;
    outPutPorts_ = GetOutPorts();
    for (auto& it : outPutPorts_) {
        if (it->format_.streamId_ == id) {
            it->DeliverBuffer(buffer);
            CAMERA_LOGI("RKCodecNode deliver buffer streamid = %{public}d", it->format_.streamId_);
            return;
        }
    }
}

RetCode RKCodecNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("RKCodecNode::Capture");
    return RC_OK;
}

RetCode RKCodecNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("RKCodecNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

REGISTERNODE(RKCodecNode, {"RKCodec"})
} // namespace OHOS::Camera
