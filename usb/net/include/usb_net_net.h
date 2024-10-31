/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#ifndef USB_NET_NET_H
#define USB_NET_NET_H

#include "hdf_base.h"
#include "hdf_device_desc.h"

#define DEFAULT_MTU          1500
#define DEFAULT_NET_HEAD_LEN 14
#define INDEX_ZERO  0
#define INDEX_ONE   1
#define INDEX_TWO   2
/**
 * ether_addr_copy - Copy an Ethernet address
 * @dst: Pointer to a six-byte array Ethernet address destination
 * @src: Pointer to a six-byte array Ethernet address source
 *
 * Please note: dst & src must both be aligned to uint16_t.
 */
#if defined(__i386) || defined(__x86_64) || defined(__s390x__) || defined(__aarch64__)
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#endif

static inline void etherAddrCopy(uint8_t *dst, const uint8_t *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
    *(uint32_t *)dst = *(const uint32_t *)src;
    *(uint16_t *)(dst + 4) = *(const uint16_t *)(src + 4);
#else
    uint16_t *a = (uint16_t *)dst;
    const uint16_t *b = (const uint16_t *)src;

    a[INDEX_ZERO] = b[INDEX_ZERO];
    a[INDEX_ONE]  = b[INDEX_ONE];
    a[INDEX_TWO]  = b[INDEX_TWO];
#endif
}

void UsbnetWriteLog(char *buff, int size, int tag);

#endif