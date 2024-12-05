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

/*
 * supply the fuction delaration of the audio effect model, which maybe used by the ISV/OEM.
 */

#ifndef EFFECT_CORE_H
#define EFFECT_CORE_H

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include "effect_host_common.h"
#include "v1_0/effect_factory.h"

/* define the struct here */
struct EffectFactoryLibListNode {
    struct EffectFactory *factLib;
    struct DListHead list;  /**< Factory library list */
    void *handle;
};

struct ControllerManagerNode {
    struct ControllerManager *ctrlMgr;
    struct DListHead list;
};

/* declare the function here */
bool IsEffectLibExist(void);
/*
int32_t RegisterEffectLibToList(void *handle, struct EffectFactory *factLib);
struct EffectFactory *GetEffectLibFromList(const char *effectLibName);
void ReleaseLibFromList(void);
int32_t RegisterControllerToList(struct ControllerManager *ctrlMgr);
struct ControllerManager *GetControllerFromList(char *effectId);
*/
#endif
