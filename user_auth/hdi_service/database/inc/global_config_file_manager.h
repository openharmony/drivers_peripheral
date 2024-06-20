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

#ifndef GLOBAL_CONFIG_FILE_MANAGER_H
#define GLOBAL_CONFIG_FILE_MANAGER_H

#include "defines.h"
#include "file_manager_utils.h"
#include "idm_common.h"
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

ResultCode LoadGlobalConfigInfo(GlobalConfigInfo *globalConfigInfo, uint32_t len, uint32_t *configInfoNum);
ResultCode UpdateGlobalConfigFile(GlobalConfigInfo *globalConfigInfo, uint32_t configInfoNum);

#ifdef __cplusplus
}
#endif

#endif // GLOBAL_CONFIG_FILE_MANAGER_H
