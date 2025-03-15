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

#ifndef HDI_CALLBACK_HANDLER_H
#define HDI_CALLBACK_HANDLER_H

#include <set>

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD001566

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {

template <typename CallbackType>
class CallbackHandler {
public:
    CallbackHandler() {}
    ~CallbackHandler() = default;

    bool RemoveCallback(const sptr<CallbackType>& cb)
    {
        if (cb == nullptr) {
            return false;
        }
        if (cbSet_.find(cb) != cbSet_.end()) {
            cbSet_.erase(cb);
        }
        return true;
    }

    bool AddCallback(const sptr<CallbackType>& cb)
    {
        if (cb == nullptr) {
            return false;
        }
        if (cbSet_.find(cb) != cbSet_.end()) {
            return true;
        }
        cbSet_.insert(cb);
        return true;
    }

    const std::set<sptr<CallbackType>>& GetCallbacks()
    {
        return cbSet_;
    }

    void Invalidate()
    {
        cbSet_.clear();
    }

private:
    std::set<sptr<CallbackType>> cbSet_;
};

}
}
}
}
}
#endif