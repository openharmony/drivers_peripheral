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

#ifndef BATTERY_THREAD_TEST_H
#define BATTERY_THREAD_TEST_H

#include "battery_thread.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
namespace {
struct BatteryThreadUnitTest {};
struct BatteryConfigUnitTest {};
struct ChargerThreadUnitTest {};
} // namespace

int32_t OpenUeventSocketTest(BatteryThread& bthread);
void UpdateEpollIntervalTest(const int32_t chargeState, BatteryThread& bthread);
int GetEpollIntervalTest(BatteryThread& bthread);
int32_t InitTest(void* service, BatteryThread& bthread);
int32_t GetEpollFdTest(BatteryThread& bthread);
int32_t InitUeventTest(BatteryThread& bthread);
int32_t GetUeventFdTest(BatteryThread& bthread);

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class OpenUeventSocketImplement {
    friend int32_t OpenUeventSocketTest(BatteryThread& bthread)
    {
        return (bthread.*privateFun)();
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class UpdateEpollIntervalImplement {
    friend void UpdateEpollIntervalTest(const int32_t chargeState, BatteryThread& bthread)
    {
        (bthread.*privateFun)(chargeState);
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class GetEpollIntervalImplement {
    friend int GetEpollIntervalTest(BatteryThread& bthread)
    {
        return (bthread.*privateFun);
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class InitImplement {
    friend int32_t InitTest(void* service, BatteryThread& bthread)
    {
        return (bthread.*privateFun)(service);
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class GetEpollFdImplement {
    friend int32_t GetEpollFdTest(BatteryThread& bthread)
    {
        return (bthread.*privateFun);
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class InitUeventImplement {
    friend int32_t InitUeventTest(BatteryThread& bthread)
    {
        return (bthread.*privateFun)();
    }
};

template <typename Tag, typename PrivateFun, PrivateFun privateFun>
class GetUeventFdImplement {
    friend int32_t GetUeventFdTest(BatteryThread& bthread)
    {
        return (bthread.*privateFun);
    }
};

template class OpenUeventSocketImplement<BatteryThreadUnitTest, decltype(&BatteryThread::OpenUeventSocket),
    &BatteryThread::OpenUeventSocket>;

template class UpdateEpollIntervalImplement<BatteryThreadUnitTest, decltype(&BatteryThread::UpdateEpollInterval),
    &BatteryThread::UpdateEpollInterval>;

template class GetEpollIntervalImplement<BatteryThreadUnitTest, decltype(&BatteryThread::epollInterval_),
    &BatteryThread::epollInterval_>;

template class InitImplement<BatteryThreadUnitTest, decltype(&BatteryThread::Init), &BatteryThread::Init>;

template class GetEpollFdImplement<BatteryThreadUnitTest, decltype(&BatteryThread::epFd_), &BatteryThread::epFd_>;

template class InitUeventImplement<BatteryThreadUnitTest, decltype(&BatteryThread::InitUevent),
    &BatteryThread::InitUevent>;

template class GetUeventFdImplement<BatteryThreadUnitTest, decltype(&BatteryThread::ueventFd_),
    &BatteryThread::ueventFd_>;
} // namespace V1_1
} // namespace Battery
} // namespace HDI
} // namespace OHOS
#endif // BATTERY_THREAD_TEST_H
