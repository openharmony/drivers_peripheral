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

#ifndef HDI_TEST_LAYER_H
#define HDI_TEST_LAYER_H
#include <queue>
#include "v1_1/display_composer_type.h"
#include "v1_0/include/idisplay_buffer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_1;

class HdiGrallocBuffer {
public:
    HdiGrallocBuffer(uint32_t seqNo, uint32_t w, uint32_t h, Composer::V1_0::PixelFormat fmt);
    ~HdiGrallocBuffer();
    BufferHandle* Get() const
    {
        return buffer_;
    }
    void SetReleaseFence(int fd);
    void SetAcquirceFence(int fd);
    int GetAcquireFence() const
    {
        return mAcquireFence;
    }
    int GetReleaseFence() const
    {
        return mReleaseFence;
    }
    int32_t SetGraphicBuffer(std::function<int32_t (const BufferHandle*, uint32_t)> realFunc);

private:
    BufferHandle* buffer_ = nullptr;
    int mAcquireFence = -1;
    int mReleaseFence = -1;
    uint32_t seqNo_ = UINT32_MAX;
    bool cacheValid_ = false;
};

class HdiTestLayer {
public:
    static const uint32_t MAX_BUFFER_COUNT = 3;
    HdiTestLayer(LayerInfo& info, uint32_t id, uint32_t displayId);
    virtual ~HdiTestLayer();
    int32_t Init(uint32_t bufferCount = MAX_BUFFER_COUNT);
    int32_t PreparePresent();

    uint32_t GetId() const
    {
        return id_;
    }
    Composer::V1_0::CompositionType GetCompType() const
    {
        return compType_;
    }

    HdiGrallocBuffer* GetFrontBuffer() const;
    HdiGrallocBuffer* GetBackBuffer() const;
    HdiGrallocBuffer* AcquireBackBuffer();

    int32_t SwapFrontToBackQ();
    int32_t SwapBackToFrontQ();

    void SetLayerPosition(const IRect& rect);
    void SetLayerCrop(const IRect& rect);
    void SetZorder(uint32_t zorder);
    void SetCompType(Composer::V1_0::CompositionType type);
    void SetReleaseFence(int fd);
    void SetAlpha(LayerAlpha alpha);
    void SetBlendType(BlendType type);
    void SetTransform(TransformType transform);
    uint32_t GetLayerBuffercount() const;

private:
    uint32_t id_;
    uint32_t displayID_;
    uint32_t layerBufferCount_;
    std::queue<std::unique_ptr<HdiGrallocBuffer>> frontBuffers_;
    std::queue<std::unique_ptr<HdiGrallocBuffer>> backBuffers_;
    LayerInfo layerInfo_ = { 0 };

#ifdef DISPLAY_COMMUNITY
    Composer::V1_0::CompositionType compType_ = Composer::V1_0::CompositionType::COMPOSITION_CLIENT;
#else
    Composer::V1_0::CompositionType compType_ = Composer::V1_0::CompositionType::COMPOSITION_DEVICE;
#endif // DISPLAY_COMMUNITY
    IRect displayRect_ = { 0 };
    IRect cropRect_ = { 0 };
    uint32_t zorder_ = 0;
    LayerAlpha alpha_ = { 0 };
    BlendType blendType_ = BLEND_SRC;
    std::unique_ptr<HdiGrallocBuffer> currentBuffer_;
    TransformType transform_ = ROTATE_NONE;
};
} // OHOS
} // HDI
} // Display
} // TEST

#endif // HDI_TEST_LAYER_H
