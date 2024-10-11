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

#ifndef HDI_COMPOSITION_CHECK_H
#define HDI_COMPOSITION_CHECK_H
#include "v1_2/display_composer_type.h"
#include "display_test_utils.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
struct Point {
    int32_t x = 0;
    int32_t y = 0;
};

class HdiCompositionCheck {
public:
    static HdiCompositionCheck& GetInstance()
    {
        static HdiCompositionCheck instace = HdiCompositionCheck();
        return instace;
    }
    void Init(uint32_t w, uint32_t h)
    {
        dispW_ = w;
        dispH_ = h;
    }
    enum {
        CHECK_CENTER,
        CHECK_VERTEX
    };
    int32_t Check(const std::vector<LayerSettings> &layers,
        const BufferHandle& clientBuffer, uint32_t checkType = CHECK_VERTEX) const;

private:
    HdiCompositionCheck() {}
    ~HdiCompositionCheck() {}
    uint32_t dispW_ = 0;
    uint32_t dispH_ = 0;
};
} // OHOS
} // HDI
} // Display
} // TEST

#endif // HDI_COMPOSITION_CHECK_H
