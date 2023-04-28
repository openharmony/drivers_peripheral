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

#include <unistd.h>
#include <vector>
#include <thread>
#include <cinttypes>
#include <securec.h>
#include <cstring>

#include "gtest/gtest.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

#include "hdf_base.h"
#include "hdf_log.h"

using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS;

namespace {
    const int SIZE_TIMES = 3;
    const int HANDLE_NUM_1 = 2;
    const int HANDLE_NUM_2 = 32;
    const int LOOP_COUNT = 10;
    const int INFO_WIDTH = 1024;
    const int INFO_HEIGHT = 1024;
}

#define HDF_LOG_TAG display_buffer_module_test

static void WriteBuffer(const BufferHandle& handle)
{
    const char VERIFY_MSG[] = "12345678, (*~*)";
    // write msg to display buffer fully.
    int strSize = strlen(VERIFY_MSG) + 1;
    int i = 0;
    char* ptr = reinterpret_cast<char *>(handle.virAddr);

    for (; i < handle.size - strSize;) {
        errno_t ret = memcpy_s(&ptr[i], sizeof(VERIFY_MSG), VERIFY_MSG, sizeof(VERIFY_MSG));
        if (ret != EOK) {
            HDF_LOGE("memcpy_s error : %d", ret);
            return;
        }
        i += strSize;
        ptr[i - 1] = 0;
    }
    for (i = i - 1; i < handle.size; i++) {
        ptr[i] = 'z';
    }

    // read all contents from buffer
    HDF_LOGD("%{public}s(%{public}d), buffer size:%{public}d, len:%{public}d",
             __func__, __LINE__, handle.size, strSize);
    // verify buffer contents from strings written.
    for (i = 0; i < handle.size - SIZE_TIMES * strSize; i = i + strSize) {
        if (strncmp(VERIFY_MSG, &ptr[i], sizeof(VERIFY_MSG)) != 0) {
            HDF_LOGD("%{public}s(%{public}d), buffer[%{public}d]:%{public}s",
                     __func__, __LINE__, i, &ptr[i]);
        }
    }

    for (i = handle.size - HANDLE_NUM_1; i < (handle.size - HANDLE_NUM_2); i++) {
        HDF_LOGD("%{public}s(%{public}d), i:%{public}d, str:%{public}s",
                 __func__, __LINE__, i, &ptr[i]);
    }
}

static void DumpBufferHandle(const BufferHandle& handle)
{
    // dump buffer handle infomation
    HDF_LOGD("-------------------------------------");
    HDF_LOGD("fd                =%{public}d",   handle.fd);
    HDF_LOGD("width             =%{public}d",   handle.width);
    HDF_LOGD("stride            =%{public}d",   handle.stride);
    HDF_LOGD("height            =%{public}d",   handle.height);
    HDF_LOGD("size              =0x%{public}x", handle.size);
    HDF_LOGD("format            =%{public}d",   handle.format);
    HDF_LOGD("usage             =0x%{public}" PRIx64 "", handle.usage);
    HDF_LOGD("key               =%{public}d",   handle.key);
    HDF_LOGD("reserveFds        =%{public}d",   handle.reserveFds);
    HDF_LOGD("reserveInts       =%{public}d",   handle.reserveInts);
    HDF_LOGD("-------------------------------------");
}

static void RunOnce(const AllocInfo& info, IDisplayBuffer* dispbuf)
{
    static int32_t count = 0;
    if (dispbuf == nullptr) {
        HDF_LOGE("Can't get IDisplayBuffer interface.");
        return;
    }
    BufferHandle* bHandle = nullptr;
    // AllocMem
    int32_t ec = dispbuf->AllocMem(info, bHandle);
    if (ec != HDF_SUCCESS || bHandle == nullptr) {
        HDF_LOGE("%{public}s, line=%{public}d, AllocMem failed. ec=0x%{public}x",
                 __func__, __LINE__, ec);
        return;
    }

    // Mmap
    void* buffer = dispbuf->Mmap(*bHandle);
    if (buffer == nullptr) {
        HDF_LOGE("Mmap failed.");
        dispbuf->FreeMem(*bHandle);
        return;
    }
    HDF_LOGD("Mmap successful");

    DumpBufferHandle(*bHandle);
    WriteBuffer(*bHandle);

    // InvalidateCache
    ec = dispbuf->InvalidateCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("InvalidateCache failed.");
        dispbuf->Unmap(*bHandle);
        dispbuf->FreeMem(*bHandle);
        return;
    }
    // InvalidateCache
    ec = dispbuf->FlushCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("flushCache failed.");
        dispbuf->Unmap(*bHandle);
        dispbuf->FreeMem(*bHandle);
        return;
    }
    HDF_LOGD("flush Cache success.");
    // free buffer
    dispbuf->Unmap(*bHandle);
    dispbuf->FreeMem(*bHandle);
    HDF_LOGD("FreeMem, finished count = %{public}d", ++count);
}

int main()
{
    HDF_LOGD("Main process start.");
    AllocInfo info;
    info.width  = INFO_WIDTH;
    info.height = INFO_HEIGHT;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    IDisplayBuffer* dispbuf = IDisplayBuffer::Get();
    for (int i = 0; i < LOOP_COUNT; i++) {
        RunOnce(info, dispbuf);
    }
    HDF_LOGD("Main process end.");
    return 0;
}