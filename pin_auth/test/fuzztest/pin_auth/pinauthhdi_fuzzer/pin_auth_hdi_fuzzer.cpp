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
#include "all_in_one_impl.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_HDI"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace {
class DummyIExecutorCallback : public HdiIExecutorCallback {
public:
    DummyIExecutorCallback(int32_t onResultResult, int32_t onGetDataResult, int32_t onTipResult,
        int32_t onMessageResult)
        : onResultResult_(onResultResult), onGetDataResult_(onGetDataResult), onTipResult_(onTipResult),
        onMessageResult_(onMessageResult)
    {
    }

    int32_t OnResult(int32_t result, const std::vector<uint8_t> &extraInfo) override
    {
        return onResultResult_;
    }

    int32_t OnGetData(const std::vector<uint8_t>& algoParameter, uint64_t authSubType, uint32_t algoVersion,
         const std::vector<uint8_t>& challenge, const std::string &pinComplexityReg) override
    {
        return onGetDataResult_;
    }

    int32_t OnTip(int32_t tip, const std::vector<uint8_t>& extraInfo) override
    {
        return onTipResult_;
    }

    int32_t OnMessage(int32_t destRole, const std::vector<uint8_t>& msg) override
    {
        return onMessageResult_;
    }

private:
    int32_t onResultResult_;
    int32_t onGetDataResult_;
    int32_t onTipResult_;
    int32_t onMessageResult_;
};

AllInOneImpl g_executorImpl(make_shared<OHOS::UserIam::PinAuth::PinAuth>());

void FillFuzzExecutorInfo(Parcel &parcel, HdiExecutorInfo &executorInfo)
{
    executorInfo.sensorId = parcel.ReadUint16();
    executorInfo.executorMatcher = parcel.ReadUint32();
    executorInfo.executorRole = static_cast<HdiExecutorRole>(parcel.ReadInt32());
    executorInfo.authType = static_cast<HdiAuthType>(parcel.ReadInt32());
    executorInfo.esl = static_cast<HdiExecutorSecureLevel>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, executorInfo.publicKey);
    FillFuzzUint8Vector(parcel, executorInfo.extraInfo);
    IAM_LOGI("success");
}

void FillFuzzIExecutorCallback(Parcel &parcel, sptr<HdiIExecutorCallback> &callbackObj)
{
    bool isNull = parcel.ReadBool();
    if (isNull) {
        callbackObj = nullptr;
    } else {
        callbackObj = new (std::nothrow) DummyIExecutorCallback(parcel.ReadInt32(),
            parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32());
        if (callbackObj == nullptr) {
            IAM_LOGE("callbackObj construct fail");
        }
    }
    IAM_LOGI("success");
}

void FillFuzzProperty(Parcel &parcel, HdiProperty &property)
{
    property.authSubType = parcel.ReadUint64();
    property.lockoutDuration = parcel.ReadInt32();
    property.remainAttempts = parcel.ReadInt32();

    IAM_LOGI("success");
}

void FuzzGetExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    HdiExecutorInfo executorInfo;
    FillFuzzExecutorInfo(parcel, executorInfo);
    g_executorImpl.GetExecutorInfo(executorInfo);
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

void FuzzSetData(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    uint64_t authSubType = parcel.ReadUint64();
    std::vector<uint8_t> data;
    FillFuzzUint8Vector(parcel, data);
    int32_t resultCode = parcel.ReadInt32();
    g_executorImpl.SetData(scheduleId, authSubType, data, resultCode);
    IAM_LOGI("end");
}

void FuzzEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    sptr<HdiIExecutorCallback> callbackObj;
    FillFuzzIExecutorCallback(parcel, callbackObj);
    g_executorImpl.Enroll(scheduleId, extraInfo, callbackObj);
    IAM_LOGI("end");
}

void FuzzAuthenticate(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    sptr<HdiIExecutorCallback> callbackObj;
    FillFuzzIExecutorCallback(parcel, callbackObj);
    g_executorImpl.Authenticate(scheduleId, templateIdList, extraInfo, callbackObj);
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

void FuzzGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    std::vector<int32_t> propertyTypes;
    FillFuzzInt32Vector(parcel, propertyTypes);
    HdiProperty property;
    FillFuzzProperty(parcel, property);
    g_executorImpl.GetProperty(templateIdList, propertyTypes, property);
    IAM_LOGI("end");
}

void FuzzSendMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    int32_t srcRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    g_executorImpl.SendMessage(scheduleId, srcRole, msg);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorInfo);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetExecutorInfo,
    FuzzOnRegisterFinish,
    FuzzSetData,
    FuzzEnroll,
    FuzzAuthenticate,
    FuzzDelete,
    FuzzCancel,
    FuzzSendMessage,
    FuzzGetProperty,
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
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::PinAuth::PinAuthHdiFuzzTest(data, size);
    return 0;
}
