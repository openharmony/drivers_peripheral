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
    CodecBuffer *inputInfos[MAX_BUFFER_NUM];
    CodecBuffer *outputInfos[MAX_BUFFER_NUM];
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
int32_t InitCodecInstance(struct CodecInstance *instance);
int32_t RunCodecInstance(struct CodecInstance *instance);
int32_t StopCodecInstance(struct CodecInstance *instance);
int32_t DestroyCodecInstance(struct CodecInstance *instance);
bool SetOemCodecBufferType(CodecBuffer *bufferToOemCodec, CodecBuffer *bufferInQueue);
int32_t AddInputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId);
int32_t AddOutputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId);
int32_t GetFdById(struct CodecInstance *instance, int32_t id);
void ReleaseInputShm(struct CodecInstance *instance);
void ReleaseOutputShm(struct CodecInstance *instance);
int32_t AddInputInfo(struct CodecInstance *instance, CodecBuffer *info);
int32_t AddOutputInfo(struct CodecInstance *instance, CodecBuffer *info);
CodecBuffer* GetInputInfo(struct CodecInstance *instance, uint32_t id);
CodecBuffer* GetOutputInfo(struct CodecInstance *instance, uint32_t id);
void ReleaseInputInfo(struct CodecInstance *instance);
void ReleaseOutputInfo(struct CodecInstance *instance);
void ResetBuffers(struct CodecInstance *instance);
void EmptyCodecBuffer(CodecBuffer *buf);
bool CopyCodecBufferWithTypeSwitch(struct CodecInstance *instance, CodecBuffer *dst,
    const CodecBuffer *src, bool ignoreBuf);
CodecBuffer* DupCodecBuffer(const CodecBuffer *src);

#ifdef __cplusplus
}
#endif
#endif  // CODEC_INSTANCE_H
