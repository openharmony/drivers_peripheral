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

#include "hdi_composition_check.h"
#include "display_test.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_1;
static void GetCheckPoints(Point center, std::vector<Point> &points)
{
    const uint32_t STEP = 3;
    points.push_back(center);
    points.push_back({center.x + STEP, center.y});
    points.push_back({center.x + STEP, center.y + STEP});
    points.push_back({center.x + STEP, center.y - STEP});
    points.push_back({center.x, center.y + STEP});
    points.push_back({center.x - STEP, center.y});
    points.push_back({center.x - STEP, center.y - STEP});
    points.push_back({center.x - STEP, center.y + STEP});
    points.push_back({center.x, center.y - STEP});
}
// simple hande the alpha it may not compatible with all scenarios
static void SimpleHandleAlpha(const LayerSettings& layers, uint32_t& color)
{
    const float INV = 1.0f / 255.0f;
    const uint32_t WHITE_TRANSPARENT = 0xffffff00;
    const int32_t ALPHA = 0xff;
    if (layers.alpha != -1) {
        switch (layers.blendType) {
            case BLEND_SRC:
                color = (color & WHITE_TRANSPARENT) | (layers.alpha & ALPHA); // get the alpha
                break;
            case BLEND_SRCOVER:
                color = color * (layers.alpha * INV);
                color = (color & WHITE_TRANSPARENT) | (layers.alpha & ALPHA); // get the alpha
                break;
            default:
                break;
        }
    }
}

static std::vector<uint32_t> GetCheckColors(const std::vector<LayerSettings> &layers, const std::vector<Point> &points)
{
    std::vector<uint32_t> colors;
    for (auto point : points) {
        uint32_t color = 0;
        for (uint32_t i = layers.size(); i > 0; i--) {
            auto layer = layers[i - 1];
            const IRect& RECT = layer.displayRect;
            // check whether the point is inside the rect
            if ((point.x >= RECT.x) && (point.x < (RECT.x + RECT.w)) && (point.y >= RECT.y) &&
                (point.y < (RECT.y + RECT.h))) {
                if (layer.compositionType != Composer::V1_0::CompositionType::COMPOSITION_VIDEO) {
                    color = layer.color;
                    SimpleHandleAlpha(layer, color);
                }
                break;
            }
        }
        colors.push_back(color);
    }
    return colors;
}

int32_t HdiCompositionCheck::Check(const std::vector<LayerSettings> &layers,
    const BufferHandle& clientBuffer, uint32_t checkType) const
{
    int ret = DISPLAY_SUCCESS;
    const int MID_POS = 2;
    // get the all check point
    std::vector<Point> points;
    for (auto layer : layers) {
        const IRect& RECT = layer.displayRect;
        if (checkType == CHECK_VERTEX) {
            GetCheckPoints({RECT.x, RECT.y}, points);
            GetCheckPoints({RECT.x, RECT.y + RECT.h}, points);
            GetCheckPoints({RECT.x + RECT.w, RECT.y}, points);
            GetCheckPoints({RECT.x + RECT.w, RECT.y + RECT.h}, points);
        } else {
            GetCheckPoints({RECT.x + RECT.w / MID_POS, RECT.y + RECT.h / MID_POS}, points); // center point
        }
    }

    // get all the check color
    std::vector<uint32_t> colors = GetCheckColors(layers, points);
    DISPLAY_TEST_CHK_RETURN((colors.size() != points.size()), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("Points and colors don't match"));
    for (uint32_t i = 0; i < points.size(); i++) {
        if ((points[i].x >= clientBuffer.width) || (points[i].x < 0) || (points[i].y < 0) ||
            (points[i].y >= clientBuffer.height)) {
            continue;
        }
        ret = CheckPixel(clientBuffer, points[i].x, points[i].y, colors[i]);
        if (ret != DISPLAY_SUCCESS) {
            DISPLAY_TEST_LOGE("check failed");
            break;
        }
    }
    return ret;
}
} // OHOS
} // HDI
} // Display
} // TEST
