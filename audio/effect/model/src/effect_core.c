/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Effect
 * @{
 *
 * @brief defines the effect core methods
 *
 * @since 4.0
 * @version 1.0
 */

#include "effect_core.h"
#include "hdf_base.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_EFFECT

/* list to manager the effect factory libs */
AEM_GET_INITED_DLIST(g_libList);

/* list to manager the effect controller */
AEM_GET_INITED_DLIST(g_controllerList);

bool IsEffectLibExist(void)
{
    bool isSupply = true;

    if (DListIsEmpty(&g_libList)) {
        HDF_LOGE("effect lib list is empty, no effect lib");
        isSupply = false;
    }

    return isSupply;
}
