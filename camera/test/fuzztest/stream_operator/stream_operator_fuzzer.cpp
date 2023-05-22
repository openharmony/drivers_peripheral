/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "common.h"
#include "stream_operator.h"

namespace OHOS {
bool CameraStreamOperatorFuzzTest(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    constexpr uint32_t sleepTime = 2;
    uint32_t code = U32_AT(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(IStreamOperator::GetDescriptor());
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<IStreamOperator> streamOperator = new OHOS::Camera::StreamOperator();
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperator, false);
    sptr<StreamOperatorStub> IpcStream = new StreamOperatorStub(streamOperator);
    CHECK_IF_PTR_NULL_RETURN_VALUE(IpcStream, false);
    
    sleep(sleepTime); // sleep two second
    IpcStream->OnRemoteRequest(code, data, reply, option);

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    CameraStreamOperatorFuzzTest(data, size);
    return 0;
}
}