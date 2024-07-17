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

#ifndef CODEC_XCOLLIE_H
#define CODEC_XCOLLIE_H

#include <string>
#include <unistd.h>
#include "codec_log_wrapper.h"

#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

namespace OHOS {
namespace HDI {
namespace Codec {
#ifdef HICOLLIE_ENABLE

class __attribute__((visibility("hidden"))) CodecXcollieTimer {
public:
    CodecXcollieTimer(const std::string &name, bool recovery = false, uint32_t timeout = 30)
    {
        unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_NOOP;
        if (recovery) {
            flag |= HiviewDFX::XCOLLIE_FLAG_RECOVERY;
        }
        index_ = HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, TimerCallback, (void *)name.c_str(), flag);
    };

    ~CodecXcollieTimer()
    {
        if (index_ == HiviewDFX::INVALID_ID) {
            return;
        }
        HiviewDFX::XCollie::GetInstance().CancelTimer(index_);
    }
private:
    static void TimerCallback(void *data)
    {
        std::string name = data != nullptr ? (char *)data : "";
        CODEC_LOGE("Service task %{public}s timeout, codec host process exit.", name.c_str());
        _exit(-1);
    }

    int32_t index_ = 0;
};

#define XCOLLIE_LISTENER(args...) HDI::Codec::CodecXcollieTimer xCollie(args)
#else
#define XCOLLIE_LISTENER(args...)
#endif
} // namespace Codec
} // namespace HDI
} // namespace OHOS
#endif // CODEC_XCOLLIE_H