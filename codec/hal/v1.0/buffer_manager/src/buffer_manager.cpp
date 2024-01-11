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

#include "buffer_manager.h"
#include <securec.h>

BufferManager::BufferManager()
{
    OsalMutexInit(&bufferQueueLock);
    OsalMutexInit(&usedBufferQueueLock);
}

BufferManager::~BufferManager()
{
    OsalMutexDestroy(&bufferQueueLock);
    OsalMutexDestroy(&usedBufferQueueLock);
}

void BufferManager::Stop()
{
    status = CODEC_STATUS_STOPPED;
}

CodecBuffer* BufferManager::GetBuffer(uint32_t timeoutMs, bool isChecking)
{
    OsalMutexLock(&bufferQueueLock);
    CodecBuffer *inputData = nullptr;
    inputData = PollBufferQueue(isChecking);
    if (inputData == nullptr) {
        if (timeoutMs == HDF_WAIT_FOREVER) {
            // release lock and wait here, and check again later when notified
            pthread_cond_wait(&inputCond, reinterpret_cast<pthread_mutex_t *>(bufferQueueLock.realMutex));
            inputData = PollBufferQueue(isChecking);
        } else if (timeoutMs > 0) {
            struct timespec time = {0};
            ConstructTimespec(&time, timeoutMs);
            // release lock and wait here, and check again later when notified or timeout
            pthread_cond_timedwait(&inputCond, reinterpret_cast<pthread_mutex_t *>(bufferQueueLock.realMutex), &time);
            inputData = PollBufferQueue(isChecking);
        }
    }
    OsalMutexUnlock(&bufferQueueLock);

    return inputData;
}

CodecBuffer* BufferManager::GetUsedBuffer(uint32_t timeoutMs, bool isChecking)
{
    OsalMutexLock(&usedBufferQueueLock);
    CodecBuffer *outputData = nullptr;
    outputData = PollUsedBufferQueue(isChecking);
    if (outputData == nullptr) {
        if (timeoutMs == HDF_WAIT_FOREVER) {
            // release lock and wait here, and check again later when notified
            pthread_cond_wait(&outputCond, reinterpret_cast<pthread_mutex_t *>(usedBufferQueueLock.realMutex));
            outputData = PollUsedBufferQueue(isChecking);
        } else if (timeoutMs > 0) {
            struct timespec time = {0};
            ConstructTimespec(&time, timeoutMs);
            // release lock and wait here, and check again later when notified or timeout
            pthread_cond_timedwait(&outputCond, reinterpret_cast<pthread_mutex_t *>(usedBufferQueueLock.realMutex),
                &time);
            outputData = PollUsedBufferQueue(isChecking);
        }
    }
    OsalMutexUnlock(&usedBufferQueueLock);

    return outputData;
}

void BufferManager::ConstructTimespec(struct timespec *time, uint32_t timeoutMs)
{
    if (time == nullptr) {
        return;
    }
    memset_s(time, sizeof(timespec), 0, sizeof(timespec));
    clock_gettime(CLOCK_REALTIME, time);
    time->tv_sec += static_cast<int32_t>(timeoutMs) / HDF_KILO_UNIT;
    time->tv_nsec += (static_cast<int32_t>(timeoutMs) % HDF_KILO_UNIT) * HDF_KILO_UNIT * HDF_KILO_UNIT;
    if (time->tv_nsec >= HDF_NANO_UNITS) {
        time->tv_nsec -= HDF_NANO_UNITS;
        time->tv_sec += 1;
    }
}

CodecBuffer* BufferManager::PollBufferQueue(bool isChecking)
{
    CodecBuffer *buffer = nullptr;
    if (bufferQueue.size() == 0) {
        return nullptr;
    }
    buffer = bufferQueue.front();
    if (!isChecking) {
        bufferQueue.pop();
    }
    return buffer;
}

CodecBuffer* BufferManager::PollUsedBufferQueue(bool isChecking)
{
    CodecBuffer *buffer = nullptr;
    if (usedBufferQueue.size() == 0) {
        return nullptr;
    }
    buffer = usedBufferQueue.front();
    if (!isChecking) {
        usedBufferQueue.pop();
    }
    return buffer;
}

void BufferManager::PutBuffer(CodecBuffer *buffer)
{
    OsalMutexLock(&bufferQueueLock);
    bufferQueue.push(buffer);
    pthread_cond_signal(&inputCond);
    OsalMutexUnlock(&bufferQueueLock);
}

void BufferManager::PutUsedBuffer(CodecBuffer *buffer)
{
    OsalMutexLock(&usedBufferQueueLock);
    usedBufferQueue.push(buffer);
    pthread_cond_signal(&outputCond);
    OsalMutexUnlock(&usedBufferQueueLock);
}

