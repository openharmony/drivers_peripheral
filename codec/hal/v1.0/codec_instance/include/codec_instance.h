/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_INSTANCE_H
#define CODEC_INSTANCE_H

#include <pthread.h>
#include <stdio.h>
#include "buffer_manager_iface.h"
#include "buffer_manager_wrapper.h"
#include "codec_oem_if.h"
#include "share_mem.h"

#define MAX_BUFFER_NUM  64
#define QUEUE_TIME_OUT  10

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    CODEC_STATUS_IDLE,
    CODEC_STATUS_STARTED,
    CODEC_STATUS_STOPED,
} CodecStatus;

struct CodecInstance {
    pthread_t task;
    ShareMemory inputBuffers[MAX_BUFFER_NUM];
    ShareMemory outputBuffers[MAX_BUFFER_NUM];
    int32_t inputBuffersCount;
    int32_t outputBuffersCount;
    InputInfo   *inputInfos[MAX_BUFFER_NUM];
    OutputInfo  *outputInfos[MAX_BUFFER_NUM];
    int32_t inputInfoCount;
    int32_t outputInfoCount;

    void *oemLibHandle;
    struct CodecOemIf *codecOemIface;

    void *bufferManagerLibHandle;
    struct BufferManagerIf *bufferManagerIface;
    struct BufferManagerWrapper *bufferManagerWrapper;

    CODEC_HANDLETYPE handle;
    CodecType codecType;
    volatile CodecStatus codecStatus;
    CodecCallback defaultCb;
    bool hasCallback;
};

struct CodecInstance* GetCodecInstance(void);
void InitCodecInstance(struct CodecInstance *instance);
void AddInputShm(struct CodecInstance *instance, CodecBufferInfo *bufferInfo);
void AddOutputShm(struct CodecInstance *instance, CodecBufferInfo *bufferInfo);
ShareMemory* GetInputShm(struct CodecInstance *instance, int32_t id);
ShareMemory* GetOutputShm(struct CodecInstance *instance, int32_t id);
int32_t GetFdById(struct CodecInstance *instance, int32_t id);
void ReleaseInputShm(struct CodecInstance *instance);
void ReleaseOutputShm(struct CodecInstance *instance);
void AddInputInfo(struct CodecInstance *instance, InputInfo *info);
void AddOutputInfo(struct CodecInstance *instance, OutputInfo *info);
InputInfo* GetInputInfo(struct CodecInstance *instance, int32_t id);
OutputInfo* GetOutputInfo(struct CodecInstance *instance, int32_t id);
void ReleaseInputInfo(struct CodecInstance *instance);
void ReleaseOutputInfo(struct CodecInstance *instance);
void ResetBuffers(struct CodecInstance *instance);
void RunCodecInstance(struct CodecInstance *instance);
void StopCodecInstance(struct CodecInstance *instance);
void DestroyCodecInstance(struct CodecInstance *instance);

#ifdef __cplusplus
}
#endif
#endif  // CODEC_INSTANCE_H
