#include "ump_packet.h"

// Optimized constructor for the most common case (1 word)
UmpPacket::UmpPacket(uint32_t w0)
{
    data_[0] = w0;
    // data_[1]..[3] are already 0 via member initialization
    word_count_ = 1;
}

// Universal constructor for variable length
UmpPacket::UmpPacket(std::initializer_list<uint32_t> words)
{
    word_count_ = static_cast<uint8_t>(std::min(words.size(), (size_t)4));
    
    size_t i = 0;
    for (uint32_t w : words) {
        if (i < 4) data_[i++] = w;
    }
}

uint32_t UmpPacket::Word(size_t index) const
{
    return (index < 4) ? data_[index] : 0;
}

uint8_t UmpPacket::WordCount() const
{
    return word_count_;
}