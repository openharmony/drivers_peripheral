/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "useriam_common.h"

#include <sys/stat.h>
#include <unistd.h>

#include "pool.h"
#include "idm_database.h"
#include "coauth.h"
#include "context_manager.h"
#include "adaptor_log.h"
#include "ed25519_key.h"

namespace OHOS {
namespace UserIam {
namespace Common {
static bool g_isInitUserIAM = false;

int32_t Init()
{
    if (InitUserAuthContextList() != RESULT_SUCCESS) {
        LOG_ERROR("init context list failed");
        goto FAIL;
    }

    if (InitResourcePool() != RESULT_SUCCESS) {
        LOG_ERROR("init resource pool failed");
        goto FAIL;
    }
    if (InitUserInfoList() != RESULT_SUCCESS) {
        LOG_ERROR("init user info failed");
        goto FAIL;
    }
    if (InitCoAuth() != RESULT_SUCCESS) {
        LOG_ERROR("init user auth failed");
        goto FAIL;
    }
    if (GenerateKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("init ed25519 key failed");
        goto FAIL;
    }
    LOG_INFO("init success");
    g_isInitUserIAM = true;
    return RESULT_SUCCESS;

FAIL:
    Close();
    return RESULT_UNKNOWN;
}

int32_t Close()
{
    DestoryUserAuthContextList();
    DestoryCoAuth();
    DestroyUserInfoList();
    DestroyResourcePool();
    DestoryEd25519KeyPair();
    g_isInitUserIAM = false;
    return RESULT_SUCCESS;
}

bool IsIAMInited()
{
    return g_isInitUserIAM;
}
} // Common
} // UserIam
} // OHOS