/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_HANDLE_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_HANDLE_H

#include <mutex>
#include <thread>
#include <stdint.h>
#include <sys/types.h>
#include <poll.h>
#include "serial_consts.h"
#include "serial_uevent_queue.h"

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

class SerialUeventHandle {
public:
    SerialUeventHandle(SerialUeventQueue* queue);
    ~SerialUeventHandle();

    int32_t Init();
    void Stop();

private:
    int SerialUeventOpen(int *fd);
    void SerialHandleUevent(const char msg[], ssize_t rcvLen);
    ssize_t SerialReadUeventMsg(int sockFd, char *buffer, size_t length);
    void SerialUeventMain();
    bool InitUeventSocket();
    void ProcessEventLoop(struct pollfd fds[], char msg[], ssize_t &rcvLen, int &errorTimes);
    void ClosePipeFd();

    SerialUeventQueue* queue_;
    std::thread thread_;
    std::mutex mutex_;
    bool running_ = false;
    int socketFd_ = INVALID_FD;
    int pipeFd_[PIPE_FD_LEN] = {INVALID_FD, INVALID_FD};
};

} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_HANDLE_H