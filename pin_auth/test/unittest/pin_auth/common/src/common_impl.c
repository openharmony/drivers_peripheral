/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IAM_COMMON_IMPL_TEST_H
#define IAM_COMMON_IMPL_TEST_H

#include "attribute.h"
#include "executor_func_common.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

Buffer *GetAuthFwkExtraInfo(uint64_t scheduleId, KeyPair *keyPair, uint8_t *challenge, uint8_t challengeSize)
{
    Attribute *data = GetAttributeDataBase(scheduleId, REMOTE_PIN_MSG_NONE);
    if (data == NULL) {
        return NULL;
    }

    Uint8Array uint8Array = {
        .data = challenge,
        .len = challengeSize,
    };
    if (SetAttributeUint8Array(data, ATTR_CHALLENGE, uint8Array) != RESULT_SUCCESS) {
        FreeAttribute(&data);
        return NULL;
    }

    Buffer *msg = CreateBufferBySize(MAX_EXECUTOR_MSG_LEN);
    if (msg == NULL) {
        FreeAttribute(&data);
        return NULL;
    }
    msg->contentSize = msg->maxSize;
    if (FormatTlvMsg(data, keyPair, msg->buf, &(msg->contentSize)) != RESULT_SUCCESS) {
        FreeAttribute(&data);
        DestroyBuffer(msg);
        return NULL;
    }

    FreeAttribute(&data);
    return msg;
}

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // IAM_COMMON_IMPL_TEST_H
