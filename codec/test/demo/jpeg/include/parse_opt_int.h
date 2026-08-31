#ifndef PARSE_OPT_INT_H
#define PARSE_OPT_INT_H

#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>

inline bool ParseOptU32(const std::string &s, uint32_t &out)
{
    if (s.empty()) {
        return false;
    }
    uint32_t value = 0;
    const char *first = s.data();
    const char *last = first + s.size();
    auto result = std::from_chars(first, last, value);
    if (result.ec != std::errc() || result.ptr != last) {
        return false;
    }
    out = value;
    return true;
}

#endif
