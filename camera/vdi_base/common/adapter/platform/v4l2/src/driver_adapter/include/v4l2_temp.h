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

#ifndef HOS_CAMERA_TEMP_H
#define HOS_CAMERA_TEMP_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <hdf_log.h>

namespace OHOS::Camera {
enum CameraBufferStatus {
    CAMERA_BUFFER_STATUS_OK = 0,
    CAMERA_BUFFER_STATUS_DROP,
    CAMERA_BUFFER_STATUS_INVALID,
};
class IBuffer {
public:
    IBuffer() {}
    ~IBuffer() {}

    int32_t GetIndex()
    {
        return index_;
    }
    uint32_t GetSize()
    {
        return size_;
    }
    void* GetVirAddress()
    {
        return virAddr_;
    }

    uint64_t GetUsage()
    {
        return usage_;
    }

    void SetIndex(const uint32_t index)
    {
        index_ = index;
        return;
    }

    void SetSize(const uint32_t size)
    {
        size_ = size;
        return;
    }

    void SetVirAddress(void* addr)
    {
        virAddr_ = addr;
        return;
    }

    void SetUsage(const uint64_t usage)
    {
        usage_ = usage;
        return;
    }
    void SetBufferStatus(const CameraBufferStatus flag)
    {
        (void)flag;
    }

private:
    int32_t index_ = -1;
    uint32_t size_ = 0;
    void* virAddr_ = nullptr;
    uint64_t usage_ = 0;
};

using FrameSpec = struct {
    int64_t bufferPoolId_;
    std::shared_ptr<IBuffer> buffer_;
};


enum AdapterCmd : uint32_t {
    CMD_AE_EXPO,
    CMD_AWB_MODE,
    CMD_AE_EXPOTIME,
    CMD_EXPOSURE_MODE,
    CMD_EXPOSURE_COMPENSATION,
    CMD_EXPOSURE_STATE,
    CMD_AWB_COLORGAINS,
    CMD_FOCUS_MODE,
    CMD_FOCUS_REGION,
    CMD_METER_MODE,
    CMD_METER_POINT,
    CMD_FLASH_MODE,
    CMD_FPS_RANGE
};

#ifdef DISABLE_LOGD
#define CAMERA_LOGD(...)
#else
#define CAMERA_LOGD(fmt, ...)                    \
    do {                                         \
        HDF_LOGD("INFO:" fmt "\n", ##__VA_ARGS__); \
    } while (0)
#endif

#define CAMERA_LOGE(fmt, ...)                     \
    do {                                          \
        HDF_LOGD("ERROR:" fmt "\n", ##__VA_ARGS__); \
    } while (0)

enum RetCode {
    RC_OK = 0,
    RC_ERROR,
};

#define CHECK_IF_NOT_EQUAL_RETURN_VALUE(arg1, arg2, ret)                                                            \
    if ((arg1) != (arg2)) {                                                                                         \
        CAMERA_LOGE("%{public}u, %{public}s is not equal to %{public}s, return %{public}s", __LINE__, #arg1, #arg2, \
                    #ret);                                                                                          \
        return (ret);                                                                                               \
    }

#define CHECK_IF_EQUAL_RETURN_VALUE(arg1, arg2, ret)                                                                   \
    if ((arg1) == (arg2)) {                                                                                            \
        CAMERA_LOGE("%{public}u, %{public}s is equal to %{public}s, return %{public}s", __LINE__, #arg1, #arg2, #ret); \
        return (ret);                                                                                                  \
    }

#define CHECK_IF_PTR_NULL_RETURN_VALUE(ptr, ret) CHECK_IF_EQUAL_RETURN_VALUE(ptr, nullptr, ret)

#define CHECK_IF_NOT_EQUAL_RETURN_VOID(arg1, arg2)                                                        \
    if ((arg1) != (arg2)) {                                                                               \
        CAMERA_LOGE("%{public}u, %{public}s is not equal to %{public}s, return", __LINE__, #arg1, #arg2); \
        return;                                                                                           \
    }

#define CHECK_IF_EQUAL_RETURN_VOID(arg1, arg2)                                                        \
    if ((arg1) == (arg2)) {                                                                           \
        CAMERA_LOGE("%{public}u, %{public}s is equal to %{public}s, return", __LINE__, #arg1, #arg2); \
        return;                                                                                       \
    }

#define CHECK_IF_PTR_NULL_RETURN_VOID(ptr) CHECK_IF_EQUAL_RETURN_VOID(ptr, nullptr)
} // namespace OHOS::Camera
#endif // HOS_CAMERA_TEMP_H
