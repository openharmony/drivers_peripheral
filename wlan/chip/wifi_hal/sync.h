/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef __WIFI_HAL_SYNC_H__
#define __WIFI_HAL_SYNC_H__

#include <pthread.h>

class Mutex {
public:
    Mutex()
    {
        pthread_mutex_init(&mMutex, nullptr);
    }
    ~Mutex()
    {
        pthread_mutex_destroy(&mMutex);
    }
    int TryLock()
    {
        return pthread_mutex_trylock(&mMutex);
    }
    int Lock()
    {
        return pthread_mutex_lock(&mMutex);
    }
    void Unlock()
    {
        pthread_mutex_unlock(&mMutex);
    }

private:
    pthread_mutex_t mMutex;
};

class Condition {
public:
    Condition()
    {
        pthread_mutex_init(&mMutex, nullptr);
        pthread_cond_init(&mCondition, nullptr);
    }
    ~Condition()
    {
        pthread_cond_destroy(&mCondition);
        pthread_mutex_destroy(&mMutex);
    }

    int Wait()
    {
        return pthread_cond_wait(&mCondition, &mMutex);
    }

    void Signal()
    {
        pthread_cond_signal(&mCondition);
    }

private:
    pthread_cond_t mCondition;
    pthread_mutex_t mMutex;
};

#endif
