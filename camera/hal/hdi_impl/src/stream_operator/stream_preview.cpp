/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "stream_preview.h"
#include <display_type.h>
#include <surface_type.h>
#include "buffer_manager.h"
#include "buffer_adapter.h"
#include "image_buffer.h"

namespace OHOS::Camera {
StreamPreview::StreamPreview()
{
}

StreamPreview::~StreamPreview()
{
    CAMERA_LOGV("enter");
}

REGISTERSTREAM(StreamPreview, {"PREVIEW", "ANALYZE"});
} // namespace OHOS::Camera
