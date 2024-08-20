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

#ifndef HDF_HOST_RNDIS_RAWAPI_H
#define HDF_HOST_RNDIS_RAWAPI_H

#include <linux/types.h>
#include <servmgr_hdi.h>
#include <hdf_remote_service.h>
#include <hdf_sbuf.h>

#include "data_fifo.h"
#include "hdf_device_desc.h"
#include "usb_raw_api.h"
#include "rndis_host.h"

/* MS-Windows uses this strange size, but RNDIS spec says 1024 minimum */
#define    CONTROL_BUFFER_SIZE        1025

/* RNDIS defines an (absurdly huge) 10 second control timeout,
 * but ActiveSync seems to use a more usual 5 second timeout
 * (which matches the USB 2.0 spec).
 */
#define    RNDIS_CONTROL_TIMEOUT_MS    (5 * 1000)

/* default filter used with RNDIS devices */
#define RNDIS_DEFAULT_FILTER ( \
    RNDIS_PACKET_TYPE_DIRECTED | \
    RNDIS_PACKET_TYPE_BROADCAST | \
    RNDIS_PACKET_TYPE_ALL_MULTICAST | \
    RNDIS_PACKET_TYPE_PROMISCUOUS)

/* Flags to require specific physical medium type for generic_rndis_bind() */
#define FLAG_RNDIS_PHYM_NOT_WIRELESS    0x0001
#define FLAG_RNDIS_PHYM_WIRELESS        0x0002
/* Flags for driver_info::data */
#define RNDIS_DRIVER_DATA_POLL_STATUS    1    /* poll status before control */

/*
 * CONTROL uses CDC "encapsulated commands" with funky notifications.
 *  - control-out:  SEND_ENCAPSULATED
 *  - interrupt-in:  RESPONSE_AVAILABLE
 *  - control-in:  GET_ENCAPSULATED
 *
 * We'll try to ignore the RESPONSE_AVAILABLE notifications.
 *
 * REVISIT some RNDIS implementations seem to have curious issues still
 * to be resolved.
 */
struct RndisMsgHdr {
    __le32    msgType;            /* RNDIS_MSG_* */
    __le32    msgLen;
    /* followed by data that varies between messages */
    __le32    requestId;
    __le32    status;
    /* ... and more */
} __attribute__ ((packed));

struct RndisDataHdr {
    __le32    msgType;         /* RNDIS_MSG_PACKET */
    __le32    msgLen;          /* RndisDataHdr + dataLen + pad */
    __le32    dataOffset;      /* 36 -- right after header */
    __le32    dataLen;         /* ... real packet size */

    __le32    oobDataOffset;      /* zero */
    __le32    oobDataLen;         /* zero */
    __le32    numOob;              /* zero */
    __le32    packetDataOffset;   /* zero */

    __le32    packetDataLen;      /* zero */
    __le32    vcHandle;            /* zero */
    __le32    reserved;             /* zero */
} __attribute__ ((packed));

struct RndisInit {                /* OUT */
    /* header and: */
    __le32    msgType;             /* RNDIS_MSG_INIT */
    __le32    msgLen;              /* 24 */
    __le32    requestId;
    __le32    majorVersion;        /* of rndis (1.0) */
    __le32    minorVersion;
    __le32    maxTransferSize;
} __attribute__ ((packed));

struct RndisInitC {               /* IN */
    /* header and: */
    __le32    msgType;                 /* RNDIS_MSG_INIT_C */
    __le32    msgLen;
    __le32    requestId;
    __le32    status;
    __le32    majorVersion;            /* of rndis (1.0) */
    __le32    minorVersion;
    __le32    deviceFlags;
    __le32    medium;                   /* zero == 802.3 */
    __le32    maxPacketsPerMessage;
    __le32    maxTransferSize;
    __le32    packetAlignment;         /* max 7; (1<<n) bytes */
    __le32    afListOffset;           /* zero */
    __le32    afListSize;             /* zero */
} __attribute__ ((packed));

struct RndisHalt {                    /* OUT (no reply) */
    /* header and: */
    __le32    msgType;                 /* RNDIS_MSG_HALT */
    __le32    msgLen;
    __le32    requestId;
} __attribute__ ((packed));

struct RndisQuery {                /* OUT */
    /* header and: */
    __le32    msgType;             /* RNDIS_MSG_QUERY */
    __le32    msgLen;
    __le32    requestId;
    __le32    oid;
    __le32    len;
    __le32    offset;
    __le32    handle;               /* zero */
} __attribute__ ((packed));

struct RndisQueryParam {
    void      *buf;
    uint32_t  oid;
    uint32_t  in_len;
} __attribute__ ((packed));

struct RndisQueryC {              /* IN */
    /* header and: */
    __le32    msgType;              /* RNDIS_MSG_QUERY_C */
    __le32    msgLen;
    __le32    requestId;
    __le32    status;
    __le32    len;
    __le32    offset;
} __attribute__ ((packed));

struct RndisSet {                /* OUT */
    /* header and: */
    __le32    msgType;            /* RNDIS_MSG_SET */
    __le32    msgLen;
    __le32    requestId;
    __le32    oid;
    __le32    len;
    __le32    offset;
    __le32    handle;               /* zero */
} __attribute__ ((packed));

struct RndisSetC {               /* IN */
    /* header and: */
    __le32    msgType;             /* RNDIS_MSG_SET_C */
    __le32    msgLen;
    __le32    requestId;
    __le32    status;
} __attribute__ ((packed));

struct RndisReset {            /* IN */
    /* header and: */
    __le32    msgType;          /* RNDIS_MSG_RESET */
    __le32    msgLen;
    __le32    reserved;
} __attribute__ ((packed));

struct RndisResetC {        /* OUT */
    /* header and: */
    __le32    msgType;          /* RNDIS_MSG_RESET_C */
    __le32    msgLen;
    __le32    status;
    __le32    addressingLost;
} __attribute__ ((packed));

struct RndisIndicate {        /* IN (unrequested) */
    /* header and: */
    __le32    msgType;         /* RNDIS_MSG_INDICATE */
    __le32    msgLen;
    __le32    status;
    __le32    length;
    __le32    offset;
    __le32    diagStatus;
    __le32    errorOffset;
    __le32    message;
} __attribute__ ((packed));

struct RndisKeepalive {    /* OUT (optionally IN) */
    /* header and: */
    __le32    msgType;            /* RNDIS_MSG_KEEPALIVE */
    __le32    msgLen;
    __le32    requestId;
} __attribute__ ((packed));

struct RndisKeepaliveC {      /* IN (optionally OUT) */
    /* header and: */
    __le32    msgType;           /* RNDIS_MSG_KEEPALIVE_C */
    __le32    msgLen;
    __le32    requestId;
    __le32    status;
} __attribute__ ((packed));

#endif /* HDF_USB_SERIAL_RAWAPI_H */
