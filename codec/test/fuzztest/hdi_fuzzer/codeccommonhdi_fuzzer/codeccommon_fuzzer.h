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

#ifndef CODECCOMMON_FUZZER_H
#define CODECCOMMON_FUZZER_H

#include <hdf_log.h>
#include "codec_omx_ext.h"
#include "v4_0/codec_types.h"
#include "v4_0/icodec_component.h"
#include "v4_0/icodec_component_manager.h"
#include "codeccallback_fuzzer.h"

using OHOS::HDI::Codec::V4_0::OmxCodecBuffer;
namespace OHOS {
namespace Codec {
    inline OHOS::sptr<OHOS::HDI::Codec::V4_0::ICodecComponent> g_component;
    inline OHOS::sptr<OHOS::HDI::Codec::V4_0::ICodecCallback> g_callback;
    inline OHOS::sptr<OHOS::HDI::Codec::V4_0::ICodecComponentManager> g_manager;
    extern uint32_t g_componentId;

    void FillDataOmxCodecBuffer(struct OmxCodecBuffer *dataFuzz);
    bool Preconditions();
    bool Destroy();
    void Release();

    template <typename T>
    void ObjectToVector(T &params, std::vector<int8_t> &vec)
    {
        int8_t *paramPointer = (int8_t *)&params;
        vec.insert(vec.end(), paramPointer, paramPointer + sizeof(params));
    }

} // namespace codec
} // namespace OHOS
#endif // CODECCOMMON_FUZZER_H
