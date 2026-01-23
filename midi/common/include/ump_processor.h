/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef UMP_PROCESSOR_H
#define UMP_PROCESSOR_H
#include <cstdint>
#include <functional>
#include "ump_packet.h"

/**
 * @brief Converts legacy MIDI 1.0 byte stream into MIDI 2.0 UMP packets.
 * * Supported Mappings:
 * - System Real-Time / Common -> MT=0x1
 * - Channel Voice (8n-En)     -> MT=0x2
 * - System Exclusive (F0..F7) -> MT=0x3 (Data Messages)
 */
class UmpProcessor {
public:
    // Callback definition for receiving generated UMPs
    using UmpCallback = std::function<void(const UmpPacket&)>;

    static constexpr size_t CV_BUFFER_SIZE = 3;
    static constexpr size_t SYSEX_BUFFER_SIZE = 6;

    UmpProcessor();

    /**
     * @brief Process a buffer of MIDI 1.0 bytes.
     * @param data Pointer to the byte array.
     * @param len Length of the byte array.
     * @param callback Function called whenever a UMP is ready.
     */
    void ProcessBytes(const uint8_t* data, size_t len, UmpCallback callback);

    // Set the destination Group (0-15) for generated UMPs
    void SetGroup(uint8_t group);

private:
    // --- Configuration ---
    uint8_t group_;

    // --- Channel / Common Message State ---
    uint8_t cv_buffer_[CV_BUFFER_SIZE];          // Buffer for Channel Voice / Common
    uint8_t cv_pos_;                // Current index in cv_buffer_
    uint8_t running_status_;        // Cached status for 8n-En messages
    uint8_t expected_len_;          // Expected data bytes (1 or 2)

    // --- SysEx State (MT=3) ---
    bool in_sysex_;                 // True if we are inside a SysEx (between F0 and F7)
    uint8_t sysex_buffer_[SYSEX_BUFFER_SIZE];       // Holds up to 6 bytes of SysEx data
    uint8_t sysex_pos_;             // Current count in sysex_buffer_
    bool sysex_has_started_;        // True if we have already sent a "Start" packet for current SysEx

    // --- Helpers ---
    int GetExpectedDataLength(uint8_t status);
    void DispatchChannelMessage(UmpCallback callback);
    void ProcessSysExData(uint8_t byte, UmpCallback callback);
    void FinalizeSysEx(UmpCallback callback);
    void DispatchSysExPacket(UmpCallback callback, uint8_t status_code, uint8_t byte_count);
    bool HandleRealTime(uint8_t byte, UmpCallback callback);
    void HandleStatusByte(uint8_t byte, UmpCallback callback);
    void HandleDataByte(uint8_t byte, UmpCallback callback);
    void HandleChannelData(uint8_t byte, UmpCallback callback);
};
#endif