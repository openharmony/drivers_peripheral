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

#include "pin_auth_hdi_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cinttypes>

#include "parcel.h"

#include "iam_logger.h"
#include "iam_fuzz_test.h"
#include "executor_impl.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_HDI

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace V1_0 {
namespace {
class DummyIExecutorCallback : public IExecutorCallback {
public:
    DummyIExecutorCallback(int32_t onResultResult, int32_t onGetDataResult)
        : onResultResult_(onResultResult), onGetDataResult_(onGetDataResult)
    {
    }

    int32_t OnResult(int32_t result, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("result %{public}d extraInfo len %{public}zu", result, extraInfo.size());
        return onResultResult_;
    }

    int32_t OnGetData(uint64_t scheduleId, const std::vector<uint8_t> &salt, uint64_t authSubType) override
    {
        IAM_LOGI("scheduleId %{public}" PRIu64 ", salt len %{public}zu authSubType %{public}" PRIu64,
            scheduleId, salt.size(), authSubType);
        return onGetDataResult_;
    }

private:
    int32_t onResultResult_;
    int32_t onGetDataResult_;
};

ExecutorImpl g_executorImpl(make_shared<OHOS::UserIam::PinAuth::PinAuth>());

void FillFuzzExecutorInfo(Parcel &parcel, ExecutorInfo &executorInfo)
{
    executorInfo.sensorId = parcel.ReadUint16();
    executorInfo.executorType = parcel.ReadUint32();
    executorInfo.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    executorInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    executorInfo.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, executorInfo.publicKey);
    FillFuzzUint8Vector(parcel, executorInfo.extraInfo);
    IAM_LOGI("success");
}

void FillFuzzTemplateInfo(Parcel &parcel, TemplateInfo &templateInfo)
{
    templateInfo.executorType = parcel.ReadUint32();
    templateInfo.lockoutDuration = parcel.ReadInt32();
    templateInfo.remainAttempts = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, templateInfo.extraInfo);
    IAM_LOGI("success");
}

void FillFuzzIExecutorCallback(Parcel &parcel, sptr<IExecutorCallback> &callbackObj)
{
    bool isNull = parcel.ReadBool();
    if (isNull) {
        callbackObj = nullptr;
    } else {
        callbackObj = new (std::nothrow) DummyIExecutorCallback(parcel.ReadInt32(), parcel.ReadInt32());
        if (callbackObj == nullptr) {
            IAM_LOGE("callbackObj construct fail");
        }
    }
    IAM_LOGI("success");
}

void FuzzGetExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    ExecutorInfo executorInfo;
    FillFuzzExecutorInfo(parcel, executorInfo);
    g_executorImpl.GetExecutorInfo(executorInfo);
    IAM_LOGI("end");
}

void FuzzGetTemplateInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t templateId = parcel.ReadUint64();
    TemplateInfo templateInfo;
    FillFuzzTemplateInfo(parcel, templateInfo);
    g_executorImpl.GetTemplateInfo(templateId, templateInfo);
    IAM_LOGI("end");
}

void FuzzOnRegisterFinish(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    std::vector<uint8_t> frameworkPublicKey;
    FillFuzzUint8Vector(parcel, frameworkPublicKey);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    g_executorImpl.OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    IAM_LOGI("end");
}

void FuzzOnSetData(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    uint64_t authSubType = parcel.ReadUint64();
    std::vector<uint8_t> data;
    FillFuzzUint8Vector(parcel, data);
    g_executorImpl.OnSetData(scheduleId, authSubType, data);
    IAM_LOGI("end");
}

void FuzzEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    sptr<IExecutorCallback> callbackObj;
    FillFuzzIExecutorCallback(parcel, callbackObj);
    g_executorImpl.Enroll(scheduleId, extraInfo, callbackObj);
    IAM_LOGI("end");
}

void FuzzAuthenticate(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    uint64_t templateId = parcel.ReadUint64();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    sptr<IExecutorCallback> callbackObj;
    FillFuzzIExecutorCallback(parcel, callbackObj);
    g_executorImpl.Authenticate(scheduleId, templateId, extraInfo, callbackObj);
    IAM_LOGI("end");
}

void FuzzDelete(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t templateId = parcel.ReadUint64();
    g_executorImpl.Delete(templateId);
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    g_executorImpl.Cancel(scheduleId);
    IAM_LOGI("end");
}

void FuzzSendCommand(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t commandId = parcel.ReadInt32();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    sptr<IExecutorCallback> callbackObj;
    FillFuzzIExecutorCallback(parcel, callbackObj);
    g_executorImpl.SendCommand(commandId, extraInfo, callbackObj);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorInfo);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetExecutorInfo,
    FuzzGetTemplateInfo,
    FuzzOnRegisterFinish,
    FuzzOnSetData,
    FuzzEnroll,
    FuzzAuthenticate,
    FuzzDelete,
    FuzzCancel,
    FuzzSendCommand,
};

void PinAuthHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace V1_0
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::PinAuth::V1_0::PinAuthHdiFuzzTest(data, size);
    return 0;
}
