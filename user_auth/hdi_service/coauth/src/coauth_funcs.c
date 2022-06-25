/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "coauth_funcs.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "defines.h"
#include "executor_message.h"
#include "pool.h"

int32_t RegisterExecutor(const ExecutorInfoHal *registerInfo, uint64_t *executorIndex)
{
    if (registerInfo == NULL || executorIndex == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }

    ExecutorInfoHal executorInfo = *registerInfo;
    int32_t ret = RegisterExecutorToPool(&executorInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("register failed");
        return ret;
    }
    *executorIndex = executorInfo.executorIndex;
    return RESULT_SUCCESS;
}

int32_t UnRegisterExecutor(uint64_t executorIndex)
{
    int32_t ret = UnregisterExecutorToPool(executorIndex);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("unregister failed");
    }
    return ret;
}