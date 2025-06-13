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
#ifndef CODEC_DFX_SERVICE_H
#define CODEC_DFX_SERVICE_H

#include <map>
#include <string>
#include <hdf_sbuf.h>
#include <hdf_base.h>
#include <securec.h>
#include "codec_component_manager_service.h"
#include "codec_component_service.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V4_0 {
class CodecDfxService : public RefBase {
public:
    ~CodecDfxService() = default;
    static CodecDfxService &GetInstance();
    static HdfSBuf* GetReply();
    void SetComponentManager(sptr<CodecComponentManagerService> manager);
    static int32_t DevCodecHostDump(struct HdfSBuf *data, struct HdfSBuf *reply);
    static int32_t GetCodecComponentListInfo(struct HdfSBuf *reply);
    static void GetCodecMemoryInfo();

protected:
    CodecDfxService() = default;

private:
    sptr<CodecComponentManagerService> managerService_;
    static CodecDfxService dfxInstance_;
    static HdfSBuf *reply_;
};

}  // namespace V4_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
#endif  // CODEC_DFX_SERVICE_H
