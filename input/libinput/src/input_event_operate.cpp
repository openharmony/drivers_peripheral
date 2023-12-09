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

#include "input_event_operate.h"
#include <set>
#include "hdf_log.h"

#define HDF_LOG_TAG InputEventOperateTag

namespace OHOS {
namespace Input {
RetStatus TransformEvent(IfInputEvent &inputEvent, libinput_event *libinputEvent)
{
    if (libinputEvent == nullptr) {
        HDF_LOGE("libinputEvent is nullptr");
        return INPUT_FAILURE;
    }
    auto type = libinput_event_get_type(libinputEvent);
    if (IsTouchEvent(type)) {
        return CopyTouchEvent(inputEvent, libinputEvent);
    }
    HDF_LOGE("unsupported event type: %{public}d", type);
    return INPUT_FAILURE;
}

RetStatus CopyTouchEvent(IfInputEvent &inputEvent, libinput_event *libinputEvent)
{
    if (libinputEvent == nullptr) {
        HDF_LOGE("libinputEvent is nullptr");
        return INPUT_FAILURE;
    }

    auto libinputTouchEvent = libinput_event_get_touch_event(libinputEvent);

    IfTouchEvent touchEvent;
    touchEvent.time = libinput_event_touch_get_time_usec(libinputTouchEvent);
    touchEvent.pressure = libinput_event_touch_get_pressure(libinputTouchEvent);
    touchEvent.seatSlot = libinput_event_touch_get_seat_slot(libinputTouchEvent);
    touchEvent.axis.major = libinput_event_get_touch_contact_long_axis(libinputTouchEvent);
    touchEvent.axis.minor = libinput_event_get_touch_contact_short_axis(libinputTouchEvent);
    touchEvent.toolType = libinput_event_touch_get_tool_type(libinputTouchEvent);
    touchEvent.sensorTime = libinput_event_get_sensortime(libinputEvent);

    IfEventData eventData;
    eventData.touchEvent = touchEvent;

    inputEvent.eventType = libinput_event_get_type(libinputEvent);
    inputEvent.data = eventData;
    return INPUT_SUCCESS;
}

bool IsTouchEvent(libinput_event_type type)
{
    std::set<libinput_event_type> touchTypeSet = {
        LIBINPUT_EVENT_TOUCH_DOWN,
        LIBINPUT_EVENT_TOUCH_UP,
        LIBINPUT_EVENT_TOUCH_MOTION,
        LIBINPUT_EVENT_TOUCH_CANCEL,
        LIBINPUT_EVENT_TOUCH_FRAME
    };
    if (touchTypeSet.find(type) == touchTypeSet.end()) {
        return false;
    }
    return true;
}
}
}
