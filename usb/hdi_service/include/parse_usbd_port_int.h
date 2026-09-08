#ifndef PARSE_USBD_PORT_INT_H
#define PARSE_USBD_PORT_INT_H

#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>

/* Digits-only port id. Rejects empty, sign, junk, and int32 overflow (stoi abort class). */
inline bool ParseUsbdPortInt32(const std::string &s, int32_t &out)
{
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    int32_t value = 0;
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
