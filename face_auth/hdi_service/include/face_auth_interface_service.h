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

#ifndef FACE_AUTH_INTERFACE_SERVICE_H
#define FACE_AUTH_INTERFACE_SERVICE_H

#include <vector>

#include "face_auth_hdi.h"

namespace OHOS {
namespace HDI {
namespace FaceAuth {
class FaceAuthInterfaceService : public IFaceAuthInterface {
public:
    FaceAuthInterfaceService();
    ~FaceAuthInterfaceService() override = default;

    int32_t GetExecutorList(std::vector<sptr<IAllInOneExecutor>> &executorList) override;
    int32_t SetBufferProducer(const sptr<BufferProducerSequenceable> &bufferProducer) override;

private:
    std::vector<sptr<IAllInOneExecutor>> executorList_;
};
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS

#endif // FACE_AUTH_INTERFACE_SERVICE_H