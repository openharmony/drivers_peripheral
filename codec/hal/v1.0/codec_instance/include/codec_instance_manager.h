/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_INSTANCE_MANAGER_H
#define CODEC_INSTANCE_MANAGER_H

#include "codec_instance.h"
#include "codec_type.h"

#ifdef __cplusplus
extern "C"
{
#endif

bool AddToCodecInstanceManager(CODEC_HANDLETYPE codecHandle, struct CodecInstance *instance);
struct CodecInstance* FindInCodecInstanceManager(CODEC_HANDLETYPE codecHandle);
void RemoveFromCodecInstanceManager(CODEC_HANDLETYPE codecHandle);

#ifdef __cplusplus
}
#endif
#endif  // CODEC_INSTANCE_MANAGER_H