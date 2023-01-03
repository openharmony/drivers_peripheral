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

#include "user_auth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "securec.h"

#include "parcel.h"

#include "iam_fuzz_test.h"

#include "auth_level.h"
#include "adaptor_memory.h"
#include "context_manager.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace V1_0 {
namespace {
UserAuthContext *GetUserAuthContext(Parcel &parcel)
{
    UserAuthContext *context = new UserAuthContext();
    if (context == nullptr) {
        return nullptr;
    }
    context->contextId = parcel.ReadUint64();
    context->userId = parcel.ReadInt32();
    context->authType = parcel.ReadUint32();
    context->authTrustLevel = parcel.ReadUint32();
    context->collectorSensorHint = parcel.ReadUint32();
    context->scheduleList = new LinkedList();
    std::vector<uint8_t> challenge(CHALLENGE_LEN);
    UserIam::Common::FillFuzzUint8Vector(parcel, challenge);
    if (memcpy_s(context->challenge, CHALLENGE_LEN, challenge.data(), CHALLENGE_LEN) != EOK) {
        delete context;
        return nullptr;
    }
    return context;
}

void FuzzGetAtl(Parcel &parcel)
{
    uint32_t acl = parcel.ReadUint32();
    uint32_t asl = parcel.ReadUint32();
    GetAtl(acl, asl);
}

void FuzzQueryScheduleAtl(Parcel &parcel)
{
    CoAuthSchedule *coAuthSchedule = new CoAuthSchedule;
    if (coAuthSchedule == nullptr) {
        return;
    }
    coAuthSchedule->scheduleId = parcel.ReadUint64();
    coAuthSchedule->authType = parcel.ReadUint32();
    coAuthSchedule->scheduleMode = static_cast<ScheduleMode>(parcel.ReadUint32());
    coAuthSchedule->associateId.contextId = parcel.ReadUint64();
    coAuthSchedule->associateId.userId = parcel.ReadInt32();
    coAuthSchedule->templateIds.num = parcel.ReadUint32();
    coAuthSchedule->templateIds.value = nullptr;
    coAuthSchedule->executorSize = parcel.ReadUint32();
    uint32_t acl = parcel.ReadUint32();
    uint32_t asl = parcel.ReadUint32();
    QueryScheduleAtl(coAuthSchedule, acl, &asl);
}

void FuzzSingleAuthTrustLevel(Parcel &parcel)
{
    int32_t userId = parcel.ReadInt32();
    uint32_t authType = parcel.ReadUint32();
    uint32_t atl = parcel.ReadUint32();
    SingleAuthTrustLevel(userId, authType, &atl);
}

void FuzzInitUserAuthContextList(Parcel &parcel)
{
    uint32_t temp = parcel.ReadUint32();
    static_cast<void>(temp);
    InitUserAuthContextList();
}

void FuzzDestoryUserAuthContextList(Parcel &parcel)
{
    uint32_t temp = parcel.ReadUint32();
    static_cast<void>(temp);
    DestoryUserAuthContextList();
}

void FuzzGenerateAuthContext(Parcel &parcel)
{
    AuthSolutionHal params = {};
    params.contextId = parcel.ReadUint64();
    params.userId = parcel.ReadInt32();
    params.authType = parcel.ReadUint32();
    params.authTrustLevel = parcel.ReadUint32();
    params.executorSensorHint = parcel.ReadUint32();
    std::vector<uint8_t> challenge(CHALLENGE_LEN);
    UserIam::Common::FillFuzzUint8Vector(parcel, challenge);
    if (memcpy_s(params.challenge, CHALLENGE_LEN, challenge.data(), CHALLENGE_LEN) != EOK) {
        return;
    }
    UserAuthContext *authContext = new UserAuthContext();
    if (authContext == nullptr) {
        return;
    }
    GenerateAuthContext(params, &authContext);
}

void FuzzGenerateIdentifyContext(Parcel &parcel)
{
    IdentifyParam params = {};
    params.contextId = parcel.ReadUint64();
    params.authType = parcel.ReadUint32();
    params.executorSensorHint = parcel.ReadUint32();
    std::vector<uint8_t> challenge(CHALLENGE_LEN);
    UserIam::Common::FillFuzzUint8Vector(parcel, challenge);
    if (memcpy_s(params.challenge, CHALLENGE_LEN, challenge.data(), CHALLENGE_LEN) != EOK) {
        return;
    }
    GenerateIdentifyContext(params);
}

void FuzzGetContext(Parcel &parcel)
{
    uint64_t contextId = parcel.ReadUint64();
    GetContext(contextId);
}

void FuzzCopySchedules(Parcel &parcel)
{
    UserAuthContext *context = GetUserAuthContext(parcel);

    LinkedList *schedules = new LinkedList();
    CopySchedules(context, &schedules);
}

void FuzzScheduleOnceFinish(Parcel &parcel)
{
    UserAuthContext *context = GetUserAuthContext(parcel);
    uint64_t scheduleId = parcel.ReadUint64();
    ScheduleOnceFinish(context, scheduleId);
}

void FuzzDestoryContext(Parcel &parcel)
{
    UserAuthContext *context = GetUserAuthContext(parcel);
    DestoryContext(context);
}

void FuzzDestoryContextbyId(Parcel &parcel)
{
    uint64_t contextId = parcel.ReadUint64();
    DestoryContextbyId(contextId);
}

void FuzzFillInContext(Parcel &parcel)
{
    UserAuthContext *context = new UserAuthContext();
    if (context == nullptr) {
        return;
    }
    ExecutorResultInfo info = {};
    info.result = parcel.ReadInt32();
    info.scheduleId = parcel.ReadUint64();
    info.templateId = parcel.ReadUint64();
    info.authSubType = parcel.ReadUint64();
    info.capabilityLevel = parcel.ReadUint32();
    info.freezingTime = parcel.ReadInt32();
    info.remainTimes = parcel.ReadInt32();
    info.rootSecret = nullptr;
    uint64_t credentialId = parcel.ReadUint64();
    FillInContext(context, &credentialId, &info);
}

using FuzzFunc = decltype(FuzzGetAtl);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetAtl,
    FuzzQueryScheduleAtl,
    FuzzSingleAuthTrustLevel,
    FuzzInitUserAuthContextList,
    FuzzDestoryUserAuthContextList,
    FuzzGenerateAuthContext,
    FuzzGenerateIdentifyContext,
    FuzzGetContext,
    FuzzCopySchedules,
    FuzzScheduleOnceFinish,
    FuzzDestoryContext,
    FuzzDestoryContextbyId,
    FuzzFillInContext,
};

void UserAuthFuzzTest(const uint8_t *data, size_t size)
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
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::UserAuth::V1_0::UserAuthFuzzTest(data, size);
    return 0;
}
