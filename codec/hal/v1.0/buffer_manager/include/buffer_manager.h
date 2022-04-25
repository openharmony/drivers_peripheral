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

#ifndef BUFFER_MANAGER_H
#define BUFFER_MANAGER_H

#include <queue>
#include <signal.h>
#include <pthread.h>
#include "codec_type.h"
#include "osal_mutex.h"

#define CODEC_STATUS_RUN        0
#define CODEC_STATUS_STOPPED    1

#define HDF_NANO_UNITS 1000000000

template <class T>
class BufferManager {
public:
    BufferManager();
    ~BufferManager();
    void Stop();
    T* GetBuffer(uint32_t timeoutMs, bool isChecking);
    T* GetUsedBuffer(uint32_t timeoutMs, bool isChecking);
    void PutBuffer(T *info);
    void PutUsedBuffer(T *info);

private:
    void ConstructTimespec(struct timespec *time,  uint32_t timeoutMs);
    T* PollBufferQueue(bool isChecking);
    T* PollUsedBufferQueue(bool isChecking);

    int32_t status;
    OsalMutex bufferQueueLock;
    OsalMutex usedBufferQueueLock;
    pthread_cond_t inputCond = PTHREAD_COND_INITIALIZER;
    pthread_cond_t outputCond = PTHREAD_COND_INITIALIZER;
    std::queue<T*> bufferQueue;
    std::queue<T*> usedBufferQueue;
};

#endif  // BUFFER_MANAGER_H
