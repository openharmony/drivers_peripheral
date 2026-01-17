/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_MIDI_V1_0_MIDIINTERFACEIMPL_H
#define OHOS_HDI_MIDI_V1_0_MIDIINTERFACEIMPL_H

#include "v1_0/imidi_interface.h"
#include <cinttypes>

namespace OHOS {
namespace HDI {
namespace Midi {
namespace V1_0 {
class MidiInterfaceImpl : public IMidiInterface {
public:
    MidiInterfaceImpl() = default;
    virtual ~MidiInterfaceImpl() = default;

    int32_t GetDeviceList(std::vector<MidiDeviceInfo> &deviceList) override;

    int32_t OpenDevice(int64_t deviceId) override;

    int32_t CloseDevice(int64_t deviceId) override;

    int32_t OpenInputPort(int64_t deviceId, uint32_t portId, const sptr<IMidiCallback> &dataCallback) override;

    int32_t CloseInputPort(int64_t deviceId, uint32_t portId) override;

    int32_t OpenOutputPort(int64_t deviceId, uint32_t portId) override;

    int32_t CloseOutputPort(int64_t deviceId, uint32_t portId) override;

    int32_t SendMidiMessages(int64_t deviceId, uint32_t portId, const std::vector<MidiMessage> &messages) override;
};
} // namespace V1_0
} // namespace Midi
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_MIDI_V1_0_MIDIINTERFACEIMPL_H