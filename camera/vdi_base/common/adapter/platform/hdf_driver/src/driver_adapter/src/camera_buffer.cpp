/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "camera_buffer.h"
#include <sys/mman.h>

namespace OHOS::Camera {

CameraBuffer::CameraBuffer(enum CameraMemType memType)
    : memoryType_(memType)
{
}

CameraBuffer::~CameraBuffer()
{
}

RetCode CameraBuffer::CameraInitMemory(struct CameraFeature feature)
{
    int32_t ret;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    ret = SendCameraCmd(CMD_QUEUE_INIT, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_QUEUE_INIT failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraBuffer::CameraReqMemory(struct CameraFeature feature, int unsigned buffCont)
{
    int32_t ret;
    bool isFailed = false;
    uint32_t capabilities = 0;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    mmapArray_.resize(buffCont);
    offArray_.resize(buffCont);
    lengthArray_.resize(buffCont);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, buffCont);
    isFailed |= !HdfSbufWriteUint32(reqData, memoryType_);
    isFailed |= !HdfSbufWriteUint32(reqData, capabilities);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_REQ_MEMORY, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_REQ_MEMORY failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    return ret;
}

RetCode CameraBuffer::CameraQueryMemory(struct CameraFeature feature,
    struct UserCameraBuffer &userBuffer, enum CameraQueryMemeryFlags flag)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);
    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, userBuffer.memType);
    isFailed |= !HdfSbufWriteUint32(reqData, userBuffer.id);
    isFailed |= !HdfSbufWriteUint32(reqData, userBuffer.planeCount);
    isFailed |= !HdfSbufWriteUint32(reqData, flag);
    CHECK_RETURN_RESULT(isFailed);
    ret = SendCameraCmd(CMD_QUERY_MEMORY, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_QUERY_MEMORY failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    if (memoryType_ == MEMTYPE_MMAP) {
        if (!HdfSbufReadUint32(respData, &userBuffer.planes[0].memory.offset)) {
            CAMERA_LOGE("fail to read offset!");
            return RC_ERROR;
        }
        if (!HdfSbufReadUint32(respData, &userBuffer.planes[0].length)) {
            CAMERA_LOGE("fail to read length!");
            return RC_ERROR;
        }
    } else if (memoryType_ == MEMTYPE_USERPTR) {
        if (!HdfSbufReadUint32(respData, &userBuffer.planeCount)) {
            CAMERA_LOGE("fail to read planeCount!");
            return RC_ERROR;
        }
    } else if (memoryType_ == MEMTYPE_DMABUF) {
        if (!HdfSbufReadUint32(respData, &userBuffer.planes[0].length)) {
            CAMERA_LOGE("fail to read length!");
            return RC_ERROR;
        }
    }

    return ret;
}

RetCode CameraBuffer::CameraAllocBuffer(struct CameraFeature feature, const std::shared_ptr<FrameSpec>& frameSpec)
{
    int32_t fd;
    struct UserCameraBuffer buf = {};
    struct UserCameraPlane planes[planeCount_] = {};
    uint32_t bufferId = frameSpec->buffer_->GetIndex();

    buf.memType = memoryType_;
    buf.id = bufferId;
    buf.planes = planes;
    buf.planeCount = planeCount_;
    if (CameraQueryMemory(feature, buf, ALLOC_FLAG) != 0) {
        CAMERA_LOGE("error: MEMTYPE[%{public}d] CameraQueryMemory failed: %{public}s\n", memoryType_, strerror(errno));
        return RC_ERROR;
    }
    switch (memoryType_) {
        case MEMTYPE_MMAP:
            fd = open("/dev/MemDev", O_RDWR);
            if (fd < 0) {
                CAMERA_LOGE("error: open fd failed\n");
                return RC_ERROR;
            }
            lengthArray_[bufferId] = buf.planes[0].length;
            offArray_[bufferId] = buf.planes[0].memory.offset;
            mmapArray_[bufferId] = mmap(NULL, buf.planes[0].length, PROT_READ|PROT_WRITE, MAP_SHARED,
                fd, offArray_[bufferId]);
            break;
        case MEMTYPE_USERPTR:
            if (buf.planeCount > frameSpec->buffer_->GetSize()) {
                CAMERA_LOGE("user buff < buf.planeCount < frameSpec->buffer_->GetSize()\n");
                return RC_ERROR;
            }
            break;
        case MEMTYPE_DMABUF:
            lengthArray_[bufferId] = buf.planes[0].length;
            mmapArray_[bufferId] = mmap(NULL, lengthArray_[bufferId], PROT_READ | PROT_WRITE, MAP_SHARED,
                frameSpec->buffer_->GetFileDescriptor(), 0);
            break;
        default:
            CAMERA_LOGE("It can not be happening - incorrect memory type\n");
            return RC_ERROR;
    }

    return RC_OK;
}

RetCode CameraBuffer::CameraStreamQueue(struct CameraFeature feature, const std::shared_ptr<FrameSpec>& frameSpec)
{
    int32_t ret;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, memoryType_);
    isFailed |= !HdfSbufWriteUint32(reqData, frameSpec->buffer_->GetIndex());
    isFailed |= !HdfSbufWriteUint32(reqData, planeCount_);
    isFailed |= !HdfSbufWriteUint32(reqData, frameSpec->buffer_->GetSize());
    if (memoryType_ == MEMTYPE_USERPTR) {
        isFailed |= !HdfSbufWriteUint64(reqData, (uint64_t)frameSpec->buffer_->GetVirAddress());
    } else if (memoryType_ == MEMTYPE_MMAP) {
        isFailed |= !HdfSbufWriteUint32(reqData, offArray_[frameSpec->buffer_->GetIndex()]);
    } else if (memoryType_ == MEMTYPE_DMABUF) {
        isFailed |= !HdfSbufWriteUint32(reqData, frameSpec->buffer_->GetFileDescriptor());
    }
    CHECK_RETURN_RESULT(isFailed);
    ret = SendCameraCmd(CMD_STREAM_QUEUE, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_STREAM_QUEUE failed, ret = %{public}d", ret);
        return RC_ERROR;
    }
    bufferMap[frameSpec->buffer_->GetIndex()] = frameSpec;

    return ret;
}

RetCode CameraBuffer::CameraStreamDequeue(struct CameraFeature feature)
{
    int32_t ret;
    uint32_t id = 0;
    bool isFailed = false;

    struct HdfSBuf *reqData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(reqData);

    struct HdfSBuf *respData = HdfSbufObtainDefaultSize();
    CHECK_SBUF_RET(respData);

    ret = SendDeviceInfo(reqData, feature, true);
    CHECK_RETURN_RESULT(ret);

    isFailed |= !HdfSbufWriteUint32(reqData, memoryType_);
    isFailed |= !HdfSbufWriteUint32(reqData, planeCount_);
    isFailed |= !HdfSbufWriteUint32(reqData, USER_BUFFER_BLOCKING);
    CHECK_RETURN_RESULT(isFailed);

    ret = SendCameraCmd(CMD_STREAM_DEQUEUE, reqData, respData);
    HdfSbufRecycle(reqData);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD_STREAM_DEQUEUE failed, ret = %{public}d", ret);
        return RC_ERROR;
    }

    if (!HdfSbufReadUint32(respData, &id)) {
        CAMERA_LOGE("fail to read Uint32 value!");
        return RC_ERROR;
    }

    CAMERA_LOGD("lengthArray_[id] = %{public}u\n", lengthArray_[id]);

    memcpy_s(bufferMap[id]->buffer_->GetVirAddress(), lengthArray_[id], mmapArray_[id], lengthArray_[id]);
    dequeueBuffer_(bufferMap[id]);

    return ret;
}

RetCode CameraBuffer::CameraReleaseBuffers(struct CameraFeature feature)
{
    struct UserCameraBuffer buf = {};
    struct UserCameraPlane planes[planeCount_] = {};

    for (int32_t i = 0; i < mmapArray_.size(); ++i) {
        buf.memType = memoryType_;
        buf.id = i;
        buf.planes = planes;
        buf.planeCount = planeCount_;

        if (CameraQueryMemory(feature, buf, RELEASE_FLAG) != 0) {
            CAMERA_LOGE("error: CameraQueryMemory failed: %{public}s\n", strerror(errno));
            return RC_ERROR;
        }
        if (memoryType_ == MEMTYPE_MMAP) {
            if (munmap(mmapArray_[i], buf.planes[0].length) < 0) {
                CAMERA_LOGE("munmap is fail\n");
                return RC_ERROR;
            }
        }
    }

    return CameraReqMemory(feature, 0);
}

void CameraBuffer::SetCameraBufferCallback(BufCallback cb)
{
    CAMERA_LOGD("SetCallback OK.");
    dequeueBuffer_ = cb;
}

RetCode CameraBuffer::Flush(char *deviceName)
{
    CAMERA_LOGD("Flush\n");

    if (deviceName == nullptr) {
        CAMERA_LOGE("Flush deviceName ptr is nullptr, line: %{public}d", __LINE__);
        return RC_ERROR;
    }
    return RC_OK;
}

} // namespace OHOS::Camera
