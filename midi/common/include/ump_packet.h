#pragma once
#include <cstdint>
#include <initializer_list>
#include <algorithm>

/**
 * @brief Represents a Universal MIDI Packet (UMP).
 */
class UmpPacket {
public:
    /**
     * @brief Optimized constructor for single-word packets (MT=1, MT=2).
     * Usage: UmpPacket(0x20903C64)
     */
    explicit UmpPacket(uint32_t w0);

    /**
     * @brief Universal constructor for multi-word packets (MT=3, MT=F, etc.).
     * Usage: UmpPacket({w0, w1})
     */
    UmpPacket(std::initializer_list<uint32_t> words);

    uint32_t Word(size_t index) const;
    uint8_t WordCount() const;

private:
    uint32_t data_[4] = { 0 }; // Zero-initialized by default
    uint8_t word_count_ = 0;
};