/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include <string.h>

#include "token_key.h"

/*
 * The key here is only for example.
 * The real scene key needs to be obtained from huks, and the key life cycle is consistent with huks key.
 */
Buffer *GetTokenHmacKey(void)
{
    return CreateBufferByData((uint8_t *)HKS_DEFAULT_USER_AT_KEY, HKS_DEFAULT_USER_AT_KEY_LEN);
}

Buffer *GetTokenAesKey(void)
{
    return CreateBufferByData((uint8_t *)HKS_DEFAULT_USER_AT_KEY, HKS_DEFAULT_USER_AT_KEY_LEN);
}

ResultCode GetTokenKey(HksAuthTokenKey *key)
{
    ResultCode ret = RESULT_SUCCESS;
    Buffer *macKey = GetTokenHmacKey();
    if (!IsBufferValid(macKey)) {
        LOG_ERROR("lack of memory");
        ret =  RESULT_NO_MEMORY;
        goto EXIT;
    }

    Buffer *cipherKey = GetTokenAesKey();
    if (!IsBufferValid(cipherKey)) {
        LOG_ERROR("lack of memory");
        ret =  RESULT_NO_MEMORY;
        goto EXIT;
    }

    if (memcpy_s(key->macKey, HKS_DEFAULT_USER_AT_KEY_LEN, macKey->buf, macKey->contentSize) != EOK) {
        LOG_ERROR("macKey copy error");
        ret =  RESULT_BAD_COPY;
        goto EXIT;
    }

    if (memcpy_s(key->cipherKey, HKS_DEFAULT_USER_AT_KEY_LEN, cipherKey->buf, cipherKey->contentSize) != EOK) {
        LOG_ERROR("cipherKey copy error");
        ret =  RESULT_BAD_COPY;
        goto EXIT;
    }

EXIT:
    DestoryBuffer(macKey);
    DestoryBuffer(cipherKey);
    return ret;
}
