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
#include "camera_dump.h"
#include "camera_hal_hisysevent.h"

#include "node_utils.h"
extern "C" {
#include <jpeglib.h>
#include <transupp.h>
}

namespace OHOS::Camera {
const unsigned long long TIME_CONVERSION_NS_S = 1000000000ULL; /* ns to s */

CodecNode::CodecNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
    CAMERA_LOGV("CodecNode::CodecNode, %{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
    jpegRotation_ = static_cast<uint32_t>(JXFORM_ROT_270);
    jpegQuality_ = 100; // 100:jpeg quality
}

CodecNode::~CodecNode()
{
    CAMERA_LOGI("~CodecNode Node exit.");
}

RetCode CodecNode::Start(const int32_t streamId)
{
    CAMERA_LOGI("CodecNode::Start streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode CodecNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("CodecNode::Stop streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode CodecNode::Flush(const int32_t streamId)
{
    CAMERA_LOGI("CodecNode::Flush streamId = %{public}d\n", streamId);
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

RetCode CodecNode::ConfigJpegOrientation(common_metadata_header_t* data)
{
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_JPEG_ORIENTATION, &entry);
    if (ret != 0 || entry.data.i32 == nullptr) {
        CAMERA_LOGE("tag not found");
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

RetCode CodecNode::ConfigJpegQuality(common_metadata_header_t* data)
{
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_JPEG_QUALITY, &entry);
    if (ret != 0) {
        CAMERA_LOGE("tag OHOS_JPEG_QUALITY not found");
        return RC_ERROR;
    }

    const int highQualityJpeg = 100;
    const int middleQualityJpeg = 95;
    const int lowQualityJpeg = 85;

    CAMERA_LOGI("OHOS_JPEG_QUALITY is = %{public}d", static_cast<int>(entry.data.u8[0]));
    if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_LOW) {
        jpegQuality_ = lowQualityJpeg;
    } else if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_MIDDLE) {
        jpegQuality_ = middleQualityJpeg;
    } else if (*entry.data.i32 == OHOS_CAMERA_JPEG_LEVEL_HIGH) {
        jpegQuality_ = highQualityJpeg;
    } else {
        jpegQuality_ = highQualityJpeg;
    }
    return RC_OK;
}

RetCode CodecNode::Config(const int32_t streamId, const CaptureMeta& meta)
{
    CAMERA_LOGD("CodecNode::Config streamid = %{public}d", streamId);
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
    if (rc != RC_OK) {
        CAMERA_LOGE("config jpeg orientation failed");
        return RC_ERROR;
    }

    rc = ConfigJpegQuality(data);
    return rc;
}

void CodecNode::EncodeJpegToMemory(uint8_t* image, JpegData jpegData,
    const char* comment, unsigned long* jpegSize, uint8_t** jpegBuf)
{
    struct jpeg_compress_struct cInfo;
    struct jpeg_error_mgr jErr;
    JSAMPROW row_pointer[1];
    int rowStride = 0;
    constexpr uint32_t colorMap = 3;
    constexpr uint32_t pixelsThick = 3;

    cInfo.err = jpeg_std_error(&jErr);

    jpeg_create_compress(&cInfo);
    cInfo.image_width = jpegData.width;
    cInfo.image_height = jpegData.height;
    cInfo.input_components = colorMap;
    cInfo.in_color_space = JCS_RGB;

    jpeg_set_defaults(&cInfo);
    CAMERA_LOGI("CodecNode::EncodeJpegToMemory jpegQuality_ is = %{public}d", jpegQuality_);
    jpeg_set_quality(&cInfo, jpegQuality_, TRUE);
    jpeg_mem_dest(&cInfo, jpegBuf, jpegSize);
    jpeg_start_compress(&cInfo, TRUE);

    if (comment) {
        jpeg_write_marker(&cInfo, JPEG_COM, (const JOCTET*)comment, strlen(comment));
    }

    rowStride = jpegData.width;
    while (cInfo.next_scanline < cInfo.image_height) {
        row_pointer[0] = &image[cInfo.next_scanline * rowStride * pixelsThick];
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

void CodecNode::Yuv422ToJpeg(std::shared_ptr<IBuffer>& buffer)
{
    CAMERA_LOGD("CodecNode::Yuv422ToJpeg begin");
    int ret = 0;
    constexpr uint8_t pixWidthRGB888 = 3;
    uint32_t tmpBufferSize = buffer->GetWidth() * buffer->GetHeight() * pixWidthRGB888;
    void* tmpBufferAddr = malloc(tmpBufferSize);
    if (tmpBufferAddr == nullptr) {
        CAMERA_LOGE("CodecNode::Yuv422ToJpeg fail, malloc tmpBufferAddr fail");
        return;
    }
    auto oldFormat = buffer->GetCurFormat();
    buffer->SetFormat(CAMERA_FORMAT_RGB_888);
    NodeUtils::BufferScaleFormatTransform(buffer, tmpBufferAddr, tmpBufferSize);
    buffer->SetFormat(oldFormat);

    uint8_t* jBuf = nullptr;
    unsigned long jpegSize = 0;

    JpegData jpegdata = {buffer->GetWidth(), buffer->GetHeight()};
    EncodeJpegToMemory((uint8_t *)tmpBufferAddr, jpegdata, nullptr, &jpegSize, &jBuf);

    ret = memcpy_s((uint8_t *)buffer->GetSuffaceBufferAddr(), buffer->GetSuffaceBufferSize(), jBuf, jpegSize);
    if (ret == 0) {
        buffer->SetEsFrameSize(jpegSize);
    } else {
        CAMERA_LOGE("CodecNode::Yuv422ToJpeg memcpy_s failed 2 , ret = %{public}d\n", ret);
        CameraHalHisysevent::WriteFaultHisysEvent(CameraHalHisysevent::GetEventName(COPY_BUFFER_ERROR),
            CameraHalHisysevent::CreateMsg("streamId:%d Yuv422ToJpeg failed ret:%d", buffer->GetStreamId(), ret));
        buffer->SetEsFrameSize(0);
    }
    CAMERA_LOGI("CodecNode::Yuv422ToJpeg jpegSize = %{public}d\n", jpegSize);
    free(jBuf);
    free(tmpBufferAddr);
    buffer->SetIsValidDataInSurfaceBuffer(true);
}

void CodecNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("CodecNode::DeliverBuffer frameSpec is null");
        return;
    }

    if (buffer->GetBufferStatus() != CAMERA_BUFFER_STATUS_OK) {
        CAMERA_LOGE("BufferStatus() != CAMERA_BUFFER_STATUS_OK");
        return NodeBase::DeliverBuffer(buffer);
    }

    int32_t id = buffer->GetStreamId();
    CAMERA_LOGI("CodecNode::DeliverBuffer, streamId[%{public}d], index[%{public}d],\
        format = %{public}d, encode =  %{public}d",
        id, buffer->GetIndex(), buffer->GetFormat(), buffer->GetEncodeType());

    if (buffer->GetEncodeType() == ENCODE_TYPE_JPEG) {
        Yuv422ToJpeg(buffer);
    } else {
        NodeUtils::BufferScaleFormatTransform(buffer);
    }

    if (buffer->GetEncodeType() == ENCODE_TYPE_H264) {
        struct timespec ts = {};
        int64_t timestamp = 0;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        timestamp = ts.tv_nsec + ts.tv_sec * TIME_CONVERSION_NS_S;
        buffer->SetEsTimestamp(timestamp);
        buffer->SetEsFrameSize(buffer->GetSuffaceBufferSize());
        buffer->SetEsKeyFrame(0);
    }

    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpBuffer("CodecNode", ENABLE_CODEC_NODE_CONVERTED, buffer);

    NodeBase::DeliverBuffer(buffer);
}

RetCode CodecNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("CodecNode::Capture streamid = %{public}d and captureId = %{public}d", streamId, captureId);
    return RC_OK;
}

RetCode CodecNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("CodecNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

REGISTERNODE(CodecNode, {"Codec"})
} // namespace OHOS::Camera
