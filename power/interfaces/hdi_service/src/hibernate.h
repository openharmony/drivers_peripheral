/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_POWER_V1_3_HIBERNATE_H
#define OHOS_HDI_POWER_V1_3_HIBERNATE_H

#include <cstdint>
#include <atomic>
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
class Hibernate {
public:
    Hibernate(const Hibernate &) = delete;
    Hibernate(const Hibernate &&) = delete;
    Hibernate &operator=(const Hibernate &) = delete;
    Hibernate &operator=(const Hibernate &&) = delete;
    ~Hibernate() {};

    void Init();
    int32_t DoHibernate();

    static Hibernate &GetInstance()
    {
        static Hibernate instance;
        return instance;
    }

private:
    Hibernate() {};
    void InitSwap();
    bool IsSwapFileExist();
    int32_t MkSwap();
    int32_t CheckSwapFile(bool &needToCreateSwapFile);
    int32_t CheckSwapFileSize(bool &isRightSize);
    int32_t CreateSwapFile();
    int32_t RemoveSwapFile();
    int32_t EnableSwap();
    int32_t GetResumeOffset(uint64_t &resumeOffset);
    int32_t GetResumeInfo(std::string &resumeInfo);
    int32_t WriteOffsetAndResume();
    int32_t WriteOffset();
    int32_t WriteResume();
    int32_t WritePowerState();

    std::atomic_bool swapFileReady_ {false};
    std::mutex initMutex_;
};
} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_3_HIBERNATE_H