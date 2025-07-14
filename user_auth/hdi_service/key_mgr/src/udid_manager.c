/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "udid_manager.h"

#include <string.h>

#include "securec.h"

#include "adaptor_log.h"

static uint8_t g_localUdidBuffer[UDID_LEN] = { 0 };

bool SetLocalUdid(const char *udid)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(udid == NULL, false);
    if (strlen(udid) != UDID_LEN) {
        LOG_ERROR("udid size is invalid");
        return false;
    }
    if (memcpy_s(g_localUdidBuffer, UDID_LEN, udid, UDID_LEN) != EOK) {
        LOG_ERROR("memcpy_s failed");
        return false;
    }
    return true;
}

static bool IsLocalUdidExit()
{
    uint8_t emptyUdid[UDID_LEN] = { 0 };
    if (memcmp(emptyUdid, g_localUdidBuffer, UDID_LEN) == 0) {
        LOG_ERROR("g_localUdidBuffer not set");
        return false;
    }
    return true;
}

bool GetLocalUdid(Uint8Array *udid)
{
    if (udid == NULL || udid->data == NULL || udid->len < UDID_LEN) {
        LOG_ERROR("invalid parameter");
        return false;
    }
    if (!IsLocalUdidExit()) {
        return false;
    }
    if (memcpy_s(udid->data, udid->len, g_localUdidBuffer, sizeof(g_localUdidBuffer)) != EOK) {
        LOG_ERROR("memcpy_s failed");
        return false;
    }
    udid->len = UDID_LEN;
    return true;
}

bool IsLocalUdid(Uint8Array udid)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(udid), false);

    if (udid.len != UDID_LEN) {
        return false;
    }

    if (memcmp(udid.data, g_localUdidBuffer, UDID_LEN) == 0) {
        return true;
    }

    return false;
}