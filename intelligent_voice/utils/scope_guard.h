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
#ifndef HDI_DEVICE_INTELL_VOICE_SCOPE_GUARD_H
#define HDI_DEVICE_INTELL_VOICE_SCOPE_GUARD_H

#include <utility>

namespace OHOS {
namespace IntelligentVoice {
namespace Utils {
template <typename Func>
class ScopeGuard {
public:
    ScopeGuard(Func &&f) : func_(std::forward<Func>(f)), active_(true)
    {
    }

    ScopeGuard(ScopeGuard &&rhs) : func_(std::move(rhs.func)), active_(rhs.active_)
    {
        rhs.Disable();
    }

    ~ScopeGuard()
    {
        if (active_) {
            func_();
        }
    }

    void Disable()
    {
        active_ = false;
    }

    bool Active() const
    {
        return active_;
    }

    void EarlyExit()
    {
        if (active_) {
            func_();
        }
        active_ = false;
    }
private:
    Func func_;
    bool active_;
    ScopeGuard() = delete;
    ScopeGuard(const ScopeGuard &) = delete;
    ScopeGuard &operator=(const ScopeGuard &) = delete;
    ScopeGuard &operator=(ScopeGuard &&) = delete;
};

// tag dispatch
struct ScopeGuardOnExit {};

template <typename Func>
inline ScopeGuard<Func> operator+(ScopeGuardOnExit, Func &&fn)
{
    return ScopeGuard<Func>(std::forward<Func>(fn));
}
}
}
}

/*
 * ScopeGuard ensure the specified function which is created by ON_SCOPE_EXIT is executed no matter how the current
 * scope exit.
 * when use ON_SCOPE_EXIT macro, the format is:
 * ON_SCOPE_EXIT {
 *     your code
 * };
*/
#define ON_SCOPE_EXIT \
    auto __onScopeGuardExit__ = OHOS::IntelligentVoice::Utils::ScopeGuardOnExit() + [&]()

#define CANCEL_SCOPE_EXIT \
    (__onScopeGuardExit__.Disable())

#define EARLY_SCOPE_EXIT \
    (__onScopeGuardExit__.EarlyExit())

#define ON_SCOPE_EXIT_WITH_NAME(variable_name) \
    auto variable_name = OHOS::IntelligentVoice::Utils::ScopeGuardOnExit() + [&]()

#endif
