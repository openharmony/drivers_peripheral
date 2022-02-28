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

#ifndef CODEC_COMPONENT_MANAGER_H
#define CODEC_COMPONENT_MANAGER_H

#include "codec_component.h"
#include "codec_component_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

struct CodecComponentManager {
    int32_t (*GetComponentNum)(); //返回num
    int32_t (*GetComponentCapabilityList)(CodecCompCapability *capList, int count); //获取到能力集List，capList由使用者释放
    int32_t (*CreateComponent)(struct CodecComponentType **component, char *compName, void *appData,
        int32_t appDataSize, struct CodecCallbackType *callbacks);  //调用OMX_GetHandle
    int32_t (*DestoryComponent)(struct CodecComponentType *component);  //调用OMX_FreeHandle
};

struct CodecComponentManager *GetCodecComponentManager(void);
void CodecComponentManagerRelease(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CODEC_COMPONENT_MANAGER_H */
/** @} */