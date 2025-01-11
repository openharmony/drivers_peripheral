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

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int VerifyAccessToken(uint32_t callerToken, const std::string &permissionName)
{
    return OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
}

int GetApiVersion(uint32_t callerToken, int32_t &apiVersion)
{
    OHOS::Security::AccessToken::HapTokenInfo hapInfo;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callerToken, hapInfo);
    apiVersion = hapInfo.apiVersion;
    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */