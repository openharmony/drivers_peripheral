/*
 * Copyright (c) 2024 Archermind Technology (Nanjing) Co. Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include "securec.h"
#include "osal_mem.h"
#include "osal_time.h"

#include "hdf_base.h"
#include "hdf_log.h"

#include "usb_ddk_pnp_loader.h"
#include "usb_ddk_interface.h"
#include "usb_net_host.h"
#include "rndis_rawapi.h"

#define HDF_LOG_TAG USB_HOST_RNDIS_RAW_API
#define URB_LEGAL_ACTUAL_LENGTH 8
#define ZERO_INDEX  0
#define ONE_INDEX   1
#define TWO_INDEX   2
#define THREE_INDEX 3
#define FOUR_INDEX  4
#define FIVE_INDEX  5

#define MSG_HEAD_LENGTH         4
#define UNION_OFFSET_LENGTH     8
#define COMMAND_COUNT_MAX       10
#define UNION_GETOFFSET_NUMBER  20
#define RNDIS_COMMAND_SLEEPTIME 40
#define RNDIS_QUERY_INPUT_LENGTH 48

/* define rndis union */
union {
    void *buf;
    struct RndisMsgHdr *header;
    struct RndisInit *init;
    struct RndisInitC *initC;
    struct RndisQuery *get;
    struct RndisQueryC *getC;
    struct RndisSet *set;
    struct RndisSetC *setC;
    struct RndisHalt *halt;
} g_u;

static int32_t UsbGetBulkEndpoint(struct UsbnetHost **ppUsbNet, const struct UsbRawEndpointDescriptor *endPoint)
{
    if ((endPoint->endpointDescriptor.bEndpointAddress & USB_DDK_ENDPOINT_DIR_MASK) == USB_DDK_DIR_IN) {
        /* get bulk in endpoint */
        (*ppUsbNet)->dataInEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
        if ((*ppUsbNet)->dataInEp == NULL) {
            HDF_LOGE("%{public}s:%{public}d allocate dataInEp failed", __func__, __LINE__);
            return HDF_FAILURE;
        }
        (*ppUsbNet)->dataInEp->addr = endPoint->endpointDescriptor.bEndpointAddress;
        (*ppUsbNet)->dataInEp->interval = endPoint->endpointDescriptor.bInterval;
        (*ppUsbNet)->dataInEp->maxPacketSize = endPoint->endpointDescriptor.wMaxPacketSize;
        HARCH_INFO_PRINT("usbNet->dataInEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
            (*ppUsbNet)->dataInEp->addr, (*ppUsbNet)->dataInEp->interval, (*ppUsbNet)->dataInEp->maxPacketSize);
    } else {
        /* get bulk out endpoint */
        (*ppUsbNet)->dataOutEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
        if ((*ppUsbNet)->dataOutEp == NULL) {
            HDF_LOGE("%{public}s:%{public}d allocate dataOutEp failed", __func__, __LINE__);
            return HDF_FAILURE;
        }
        (*ppUsbNet)->dataOutEp->addr = endPoint->endpointDescriptor.bEndpointAddress;
        (*ppUsbNet)->dataOutEp->interval = endPoint->endpointDescriptor.bInterval;
        (*ppUsbNet)->dataOutEp->maxPacketSize = endPoint->endpointDescriptor.wMaxPacketSize;
        HARCH_INFO_PRINT("usbNet->dataOutEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
            (*ppUsbNet)->dataOutEp->addr, (*ppUsbNet)->dataOutEp->interval, (*ppUsbNet)->dataOutEp->maxPacketSize);
    }
    return HDF_SUCCESS;
}

static void UsbParseConfigDescriptorProcess(struct UsbnetHost **ppUsbNet,
    const struct UsbRawInterface *interface, uint8_t interfaceIndex)
{
    uint8_t ifaceClass   = interface->altsetting->interfaceDescriptor.bInterfaceClass;
    uint8_t numEndpoints = interface->altsetting->interfaceDescriptor.bNumEndpoints;
    HARCH_INFO_PRINT("ifaceClass=%{public}d, numEndpoints=%{public}d", ifaceClass, numEndpoints);
    switch (ifaceClass) {
        case USB_DDK_CLASS_WIRELESS_CONTROLLER: //USB_DDK_CLASS_COMM:
            (*ppUsbNet)->ctrlIface = interfaceIndex;
            HARCH_INFO_PRINT("ctrlInface:%{public}d", interfaceIndex);
            (*ppUsbNet)->statusEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
            if ((*ppUsbNet)->statusEp == NULL) {
                HDF_LOGE("%{public}s:%{public}d allocate endpoint failed", __func__, __LINE__);
                break;
            }
            /* get the first endpoint by default */
            (*ppUsbNet)->statusEp->addr = interface->altsetting->endPoint[0].endpointDescriptor.bEndpointAddress;
            (*ppUsbNet)->statusEp->interval = interface->altsetting->endPoint[0].endpointDescriptor.bInterval;
            (*ppUsbNet)->statusEp->maxPacketSize = interface->altsetting->endPoint[0].endpointDescriptor.wMaxPacketSize;

            HARCH_INFO_PRINT("usbNet->statusEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
                (*ppUsbNet)->statusEp->addr, (*ppUsbNet)->statusEp->interval, (*ppUsbNet)->statusEp->maxPacketSize);
            break;
        case USB_DDK_CLASS_CDC_DATA:
            (*ppUsbNet)->dataIface = interfaceIndex;
            HARCH_INFO_PRINT("dataIface:%{public}d", interfaceIndex);
            for (uint8_t j = 0; j < numEndpoints; j++) {
                const struct UsbRawEndpointDescriptor *endPoint = &interface->altsetting->endPoint[j];
                if (UsbGetBulkEndpoint(ppUsbNet, endPoint) != HDF_SUCCESS) {
                    HARCH_INFO_PRINT("");
                    break;
                }
                HARCH_INFO_PRINT("");
            }
            break;
        default:
            HARCH_INFO_PRINT("wrong descriptor type");
            break;
    }
}

static int32_t UsbParseConfigDescriptor(struct UsbnetHost **ppUsbNet)
{
    const struct UsbRawInterface *interface = (*ppUsbNet)->config->interface[0];
    //set 0 interface and 1 interface data endpoint and ctrl endpoint
    int32_t ret = UsbRawClaimInterface((*ppUsbNet)->devHandle, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d claim interface failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("");
    UsbParseConfigDescriptorProcess(ppUsbNet, interface, 0);

    const struct UsbRawInterface *interface1 = (*ppUsbNet)->config->interface[1];
    ret = UsbRawClaimInterface((*ppUsbNet)->devHandle, 1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d claim interface failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("");
    UsbParseConfigDescriptorProcess(ppUsbNet, interface1, 1);
    return HDF_SUCCESS;
}

/*
 * RNDIS indicate messages.
 */
static void HostRndisMsgIndicate(struct UsbnetHost *usbNet, struct RndisIndicate *msg, int buflen)
{
    HARCH_INFO_PRINT("begin");
    uint32_t status = CPU_TO_LE32(msg->status);
    switch (status) {
        case RNDIS_STATUS_MEDIA_CONNECT:
            HARCH_INFO_PRINT("rndis media connect");
            break;
        case RNDIS_STATUS_MEDIA_DISCONNECT:
            HARCH_INFO_PRINT("rndis media disconnect");
            break;
        default:
            HARCH_INFO_PRINT("rndis indication: 0x%{public}08x\n", status);
            /* fall-through */
    }
}

static void UsbnetHostHandleNonRsp(struct UsbnetHost *usbNet,
    struct RndisMsgHdr *buf, int buflen, uint32_t msgType)
{
    switch (msgType) {
        /* fault/event */
        case RNDIS_MSG_INDICATE:
            HostRndisMsgIndicate(usbNet, (void *)buf, buflen);
            break;
        case RNDIS_MSG_KEEPALIVE: {
                /* ping */
                struct RndisKeepaliveC *msg = (void *)buf;
                msg->msgType = CPU_TO_LE32(RNDIS_MSG_KEEPALIVE_C);
                msg->msgLen = CPU_TO_LE32(sizeof(struct RndisKeepaliveC));
                msg->status = CPU_TO_LE32(RNDIS_STATUS_SUCCESS);

                struct UsbnetHostCmdParam cmdParam = {};
                cmdParam.cmd = USB_DDK_CDC_SEND_ENCAPSULATED_COMMAND;
                cmdParam.reqtype = USB_DDK_DIR_OUT|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE;
                cmdParam.value = 0;
                cmdParam.index = usbNet->curInterfaceNumber;
                cmdParam.data = msg;
                cmdParam.size = sizeof(struct RndisKeepaliveC);
                int32_t retval = UsbnetHostWriteCmdSync(usbNet, cmdParam);
                HARCH_INFO_PRINT("retval = %{public}d", retval);
                if (retval < 0) {
                    HARCH_INFO_PRINT("rndis keepalive err %{public}d\n", retval);
                }
            }
            break;
        default:
            HARCH_INFO_PRINT("unexpected rndis msg %{public}08x len %{public}d\n",
                CPU_TO_LE32(buf->msgType), CPU_TO_LE32(buf->msgLen));
            break;
    }
}

static int32_t UsbnetHostHandleMsg(struct UsbnetHost *usbNet, struct RndisMsgHdr *buf, int buflen, uint32_t xid)
{
    uint32_t msgType = CPU_TO_LE32(buf->msgType);
    uint32_t msgLen = CPU_TO_LE32(buf->msgLen);
    uint32_t status = CPU_TO_LE32(buf->status);
    uint32_t requestId =  (__force uint32_t)buf->requestId;
    uint32_t rsp = CPU_TO_LE32(buf->msgType) | RNDIS_MSG_COMPLETION;
    HARCH_INFO_PRINT("rndis reply msgType = %{public}x, msgLen = %{public}x,"
        "status = %{public}x, requestId = %{public}x",
        msgType, msgLen, status, requestId);

    if (msgType == rsp) {
        if (requestId == xid) {
            HARCH_INFO_PRINT("rndis reply status %{public}08x\n", status);
            HARCH_INFO_PRINT("rndis reply rsp %{public}08x\n", rsp);
            if (rsp == RNDIS_MSG_RESET_C) {
                return HDF_SUCCESS;
            }

            if (RNDIS_STATUS_SUCCESS == status) {
                return HDF_SUCCESS;
            }

            HARCH_INFO_PRINT("rndis reply status %{public}08x\n", status);
            return -EL3RST;
        }
        /* then likely retry */
    } else {
        HARCH_INFO_PRINT("unexpected rndis msg %{public}08x len %{public}d\n", CPU_TO_LE32(buf->msgType), msgLen);
        UsbnetHostHandleNonRsp(usbNet, buf, buflen, msgType);
    }
    return HDF_SUCCESS;
}

/*
 * RPC done RNDIS-style.  Caller guarantees:
 * - message is properly byteswapped
 * - there's no other request pending
 * - buf can hold up to 1KB response (required by RNDIS spec)
 * On return, the first few entries are already byteswapped.
 *
 * Call context is likely probe(), before interface name is known,
 * which is why we won't try to use it in the diagnostics.
 */
static int32_t HostRndisCommand(struct UsbnetHost *usbNet, struct RndisMsgHdr *buf, int buflen)
{
    HARCH_INFO_PRINT("begin");
    uint32_t msgType = CPU_TO_LE32(buf->msgType);
    uint32_t xid = 0;

    /* Issue the request; xid is unique, don't bother byteswapping it */
    if (msgType != RNDIS_MSG_HALT && msgType != RNDIS_MSG_RESET) {
        xid = usbNet->xid++;
        if (!xid) {
            xid = usbNet->xid++;
        }
        buf->requestId = (__force __le32) xid;
    }
    HARCH_INFO_PRINT("msgType= %{public}d, xid = %{public}d", msgType, xid);
    struct UsbnetHostCmdParam cmdParam = {};
    cmdParam.cmd = USB_DDK_CDC_SEND_ENCAPSULATED_COMMAND;
    cmdParam.reqtype = USB_DDK_DIR_OUT|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE;
    cmdParam.value = 0;
    cmdParam.index = usbNet->curInterfaceNumber;
    cmdParam.data = buf;
    cmdParam.size = CPU_TO_LE32(buf->msgLen);

    int retval = UsbnetHostWriteCmdSync(usbNet, cmdParam);
    HARCH_INFO_PRINT("retval = %{public}d", retval);
    if (retval < 0 || xid == 0) {
        return retval;
    }
    UsbnetWriteLog((char *)buf, CPU_TO_LE32(buf->msgLen), 0);
    HARCH_INFO_PRINT("rndis xid %{public}d\n", xid);
    uint32_t count = 0;
    /* Poll the control channel; the request probably completed immediately */
    for (count = 0; count < COMMAND_COUNT_MAX; count++) {
        HARCH_INFO_PRINT("count = %{public}d, buflen = %{public}d", count, buflen);
        memset_s(buf, CONTROL_BUFFER_SIZE, 0, CONTROL_BUFFER_SIZE);
        cmdParam.cmd = USB_DDK_CDC_GET_ENCAPSULATED_RESPONSE;
        cmdParam.reqtype = USB_DDK_DIR_IN|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE;
        cmdParam.value = 0;
        cmdParam.index = usbNet->curInterfaceNumber;
        cmdParam.data = buf;
        cmdParam.size = buflen;
        retval= UsbnetHostWriteCmdSync(usbNet, cmdParam);
        HARCH_INFO_PRINT("retval = %{public}d", retval);
        UsbnetWriteLog((char *)buf, buflen, 0);

        if (retval > URB_LEGAL_ACTUAL_LENGTH) {
            return UsbnetHostHandleMsg(usbNet, buf, buflen, xid);
        } else {
            /* device probably issued a protocol stall; ignore */
            HARCH_INFO_PRINT("rndis response error = %{public}d", retval);
        }
        OsalMSleep(RNDIS_COMMAND_SLEEPTIME);
    }
    HARCH_INFO_PRINT("rndis response timeout");
    return HDF_ERR_TIMEOUT;
}

/* Performs a query for @oid along with 0 or more bytes of payload as
 * specified by @in_len. If @replyLen is not set to -1 then the reply
 * length is checked against this value, resulting in an error if it
 * doesn't match.
 *
 * NOTE: Adding a payload exactly or greater than the size of the expected
 * response payload is an evident requirement MSFT added for ActiveSync.
 *
 * The only exception is for OIDs that return a variably sized response,
 * in which case no payload should be added.  This undocumented (and
 * nonsensical!) issue was found by sniffing protocol requests from the
 * ActiveSync 4.1 Windows driver.
 */
static int32_t HostRndisQuery(struct UsbnetHost *usbNet, struct RndisQueryParam queryParam, void **reply, int *replyLen)
{
    HARCH_INFO_PRINT("begin");
    int retval;
    union {
        void *buf;
        struct RndisMsgHdr *header;
        struct RndisQuery *get;
        struct RndisQueryC *getC;
    } uq;

    uq.buf = queryParam.buf;
    memset_s(uq.get, sizeof(struct RndisQuery) + queryParam.in_len, 0, sizeof(struct RndisQuery) + queryParam.in_len);
    uq.get->msgType = CPU_TO_LE32(RNDIS_MSG_QUERY);
    uq.get->msgLen  = CPU_TO_LE32(sizeof(struct RndisQuery) + queryParam.in_len);
    uq.get->oid = CPU_TO_LE32(queryParam.oid);
    uq.get->len = CPU_TO_LE32(queryParam.in_len);
    uq.get->offset = CPU_TO_LE32(UNION_GETOFFSET_NUMBER);

    retval = HostRndisCommand(usbNet, uq.header, CONTROL_BUFFER_SIZE);
    HARCH_INFO_PRINT("retval = %{public}d", retval);
    HARCH_INFO_PRINT("RNDIS_MSG_QUERY(0x%{public}08x) %{public}d\n", queryParam.oid, retval);
    if (retval < 0) {
        HDF_LOGE("RNDIS_MSG_QUERY(0x%{public}08x) failed, %{public}d", queryParam.oid, retval);
        return retval;
    }

    uint32_t off = CPU_TO_LE32(uq.getC->offset);
    uint32_t len = CPU_TO_LE32(uq.getC->len);

    HARCH_INFO_PRINT("off = %{public}d, len = %{public}d, retval = %{public}d", off, len, retval);
    if ((off > CONTROL_BUFFER_SIZE - UNION_OFFSET_LENGTH) || (len > CONTROL_BUFFER_SIZE - UNION_OFFSET_LENGTH - off)) {
        goto response_error;
    }

    if (*replyLen != -1 && len != *replyLen) {
        goto response_error;
    }

    *reply = (unsigned char *) &uq.getC->requestId + off;
    *replyLen = len;

    HARCH_INFO_PRINT("*replyLen = %{public}d, retval = %{public}d", len, retval);
    return retval;

response_error:
    HDF_LOGE("RNDIS_MSG_QUERY(0x%{public}08x) invalid response - off %{public}d len %{public}d",
        queryParam.oid, off, len);

    return -EDOM;
}

static void HostRndisInitUsbnet(struct UsbnetHost **ppUsbNet, int32_t *retval)
{
    /* max transfer (in spec) is 0x4000 at full speed, but for
     * TX we'll stick to one Ethernet packet plus RNDIS framing.
     * For RX we handle drivers that zero-pad to end-of-packet.
     * Don't let userspace change these settings.
     *
     * NOTE: there still seems to be wierdness here, as if we need
     * to do some more things to make sure WinCE targets accept this.
     * They default to jumbograms of 8KB or 16KB, which is absurd
     * for such low data rates and which is also more than Linux
     * can usually expect to allocate for SKB data...
     */
    (*ppUsbNet)->net.hardHeaderLen += sizeof(struct RndisDataHdr);
    (*ppUsbNet)->net.hardMtu = (*ppUsbNet)->net.mtu + (*ppUsbNet)->net.hardHeaderLen;
    HARCH_INFO_PRINT("hardHeaderLen = %{public}d, hardMtu = %{public}d\n",
        (*ppUsbNet)->net.hardHeaderLen, (*ppUsbNet)->net.hardMtu);
    (*ppUsbNet)->net.maxpacket = (*ppUsbNet)->dataOutEp->maxPacketSize;

    HARCH_INFO_PRINT("maxpacket = %{public}d\n", (*ppUsbNet)->net.maxpacket);
    if ((*ppUsbNet)->net.maxpacket == 0) {
        HDF_LOGE("usbNet->maxpacket can't be 0");
        *retval = HDF_ERR_INVALID_PARAM;
        return;
    }

    (*ppUsbNet)->net.rxUrbSize = (*ppUsbNet)->net.hardMtu + ((*ppUsbNet)->net.maxpacket + 1);
    (*ppUsbNet)->net.rxUrbSize &= ~((*ppUsbNet)->net.maxpacket - 1);
    HARCH_INFO_PRINT("rxUrbSize = %{public}d\n", (*ppUsbNet)->net.rxUrbSize);
}

static void HostRndisUpdateMtu(struct UsbnetHost **ppUsbNet, int32_t *retval)
{
    uint32_t tmp = CPU_TO_LE32(g_u.initC->maxTransferSize);
    if (tmp < (*ppUsbNet)->net.hardMtu) {
        if (tmp <= (*ppUsbNet)->net.hardHeaderLen) {
            HARCH_INFO_PRINT("RNDIS init failed, %{public}d", *retval);
            HDF_LOGE("usbNet can't take %{public}u byte packets (max %{public}u)", (*ppUsbNet)->net.hardMtu, tmp);
            *retval = HDF_ERR_INVALID_PARAM;
        }
        HARCH_INFO_PRINT("usbNet can't take %{public}u byte packets (max %{public}u) adjusting MTU to %{public}u\n",
            (*ppUsbNet)->net.hardMtu, tmp, tmp - (*ppUsbNet)->net.hardHeaderLen);
        HDF_LOGW("usbNet can't take %{public}u byte packets (max %{public}u) adjusting MTU to %{public}u",
            (*ppUsbNet)->net.hardMtu, tmp, tmp - (*ppUsbNet)->net.hardHeaderLen);
        (*ppUsbNet)->net.hardMtu = tmp;
        (*ppUsbNet)->net.mtu = (*ppUsbNet)->net.hardMtu - (*ppUsbNet)->net.hardHeaderLen;
    }
    HARCH_INFO_PRINT("hard mtu %{public}u (%{public}u from usbNet), align %{public}d\n",
        (*ppUsbNet)->net.hardMtu, tmp, 1 << CPU_TO_LE32(g_u.initC->packetAlignment));
}

static void HostRndisSetmacAddrByBp(struct UsbnetHost **ppUsbNet, int32_t *retval)
{
    int replyLen = MAC_ADDR_SIZE;
    unsigned char *bp;
    struct RndisQueryParam queryParam = {g_u.buf, RNDIS_OID_802_3_PERMANENT_ADDRESS, RNDIS_QUERY_INPUT_LENGTH};
    *retval = HostRndisQuery(*ppUsbNet, queryParam, (void **)&bp, &replyLen);
    if (*retval < 0) {
        HDF_LOGE("rndis get ethaddr, %{public}d", *retval);
        *retval = HDF_ERR_NOPERM;
    }

    HARCH_INFO_PRINT("bp 1= %{public}x", bp[ZERO_INDEX]);
    HARCH_INFO_PRINT("bp 2= %{public}x", bp[ONE_INDEX]);
    HARCH_INFO_PRINT("bp 3= %{public}x", bp[TWO_INDEX]);
    HARCH_INFO_PRINT("bp 4= %{public}x", bp[THREE_INDEX]);
    HARCH_INFO_PRINT("bp 5= %{public}x", bp[FOUR_INDEX]);
    HARCH_INFO_PRINT("bp 6= %{public}x", bp[FIVE_INDEX]);

    if (bp[0] & 0x02) {
        HARCH_INFO_PRINT("not GetmacAddr");
        (*ppUsbNet)->net.isGetmacAddr = 0;
        size_t macAddrLen = sizeof((*ppUsbNet)->net.macAddr) / sizeof((*ppUsbNet)->net.macAddr[0]);
        memset_s((*ppUsbNet)->net.macAddr, macAddrLen, 0, macAddrLen);
    } else {
        HARCH_INFO_PRINT("GetmacAddr");
        (*ppUsbNet)->net.isGetmacAddr = 1;
        etherAddrCopy((*ppUsbNet)->net.macAddr, bp);
    }
}

static void HostRndisSetmacAddr(struct UsbnetHost **ppUsbNet, int32_t *retval)
{
    __le32 *phym = NULL;
    __le32 phym_unspec;
    int replyLen = sizeof(__le32);
    /* Check physical medium */
    struct RndisQueryParam queryParam = {g_u.buf, RNDIS_OID_GEN_PHYSICAL_MEDIUM, replyLen};
    *retval = HostRndisQuery(*ppUsbNet, queryParam, (void **)&phym, &replyLen);
    if (*retval != 0 || !phym) {
        /* OID is optional so don't fail here. */
        phym_unspec = CPU_TO_LE32(RNDIS_PHYSICAL_MEDIUM_UNSPECIFIED);
        phym = &phym_unspec;
    }

    if (((*ppUsbNet)->flags & FLAG_RNDIS_PHYM_WIRELESS) &&
        CPU_TO_LE32(*phym) != RNDIS_PHYSICAL_MEDIUM_WIRELESS_LAN) {
        HDF_LOGE("driver requires wireless physical medium, but device is not");
        *retval = HDF_ERR_NOPERM;
    }

    if (((*ppUsbNet)->flags & FLAG_RNDIS_PHYM_NOT_WIRELESS) &&
        CPU_TO_LE32(*phym) == RNDIS_PHYSICAL_MEDIUM_WIRELESS_LAN) {
        HDF_LOGE("driver requires non-wireless physical medium, but device is wireless");
        *retval = HDF_ERR_NOPERM;
    }

    /* Get designated host ethernet address */
    HostRndisSetmacAddrByBp(ppUsbNet, retval);
}

static int32_t HostRndisInitUnion(struct UsbnetHost *usbNet, int32_t *retval)
{
    int32_t ret = HDF_SUCCESS;
    g_u.buf = OsalMemAlloc(CONTROL_BUFFER_SIZE);
    if (!g_u.buf) {
        HDF_LOGE("g_u.buf can't be 0");
        ret = HDF_ERR_MALLOC_FAIL;
    }

    g_u.init->msgType = CPU_TO_LE32(RNDIS_MSG_INIT);
    g_u.init->msgLen  = CPU_TO_LE32(sizeof(struct RndisInit));
    g_u.init->majorVersion = CPU_TO_LE32(1);
    g_u.init->minorVersion = CPU_TO_LE32(0);

    g_u.init->maxTransferSize = CPU_TO_LE32((usbNet)->net.rxUrbSize);
    *retval = HostRndisCommand(usbNet, g_u.header, CONTROL_BUFFER_SIZE);
    if (*retval < 0) {
        /* it might not even be an RNDIS device!! */
        HARCH_INFO_PRINT("RNDIS init failed, %{public}d", *retval);
        HDF_LOGE("RNDIS init failed, %{public}d", *retval);
        ret = HDF_DEV_ERR_OP;
    }
    return ret;
}

static int32_t HostRndisEnableDataTransfers(struct UsbnetHost *usbNet)
{
    int32_t ret = HDF_SUCCESS;
    /* set a nonzero filter to enable data transfers */
    memset_s(g_u.set, sizeof(struct RndisSet), 0, sizeof(struct RndisSet));
    g_u.set->msgType = CPU_TO_LE32(RNDIS_MSG_SET);
    g_u.set->msgLen = CPU_TO_LE32(MSG_HEAD_LENGTH + sizeof(struct RndisSet));
    g_u.set->oid = CPU_TO_LE32(RNDIS_OID_GEN_CURRENT_PACKET_FILTER);
    g_u.set->len = CPU_TO_LE32(MSG_HEAD_LENGTH);
    g_u.set->offset = CPU_TO_LE32(sizeof(struct RndisSet) - UNION_OFFSET_LENGTH);
    *(__le32 *)(g_u.buf + sizeof(struct RndisSet)) = CPU_TO_LE32(RNDIS_DEFAULT_FILTER);
    int32_t retval = HostRndisCommand(usbNet, g_u.header, CONTROL_BUFFER_SIZE);
    if (retval < 0) {
        HDF_LOGE("rndis set packet filter, %{public}d", retval);
        ret = HDF_FAILURE;
    }
    OsalMemFree(g_u.buf);
    return ret;
}

/* function
    1.get usb endpoints info
    2.init usb device
    3.get usb device adrress and status
    4.set usb device work
*/
static int32_t HostRndisBind(struct UsbnetHost *usbNet)
{
    int32_t retval = 0;
    int32_t ret = UsbParseConfigDescriptor(&usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbParseConfigDescriptor failed", __func__, __LINE__);
        UsbRawFreeConfigDescriptor(usbNet->config);
        usbNet->config = NULL;
        return ret;
    }

    HostRndisInitUsbnet(&usbNet, &retval);
    if (retval == HDF_ERR_INVALID_PARAM) {
        HDF_LOGE("%{public}s:%{public}d HostRndisInitUsbnet failed", __func__, __LINE__);
        return retval;
    }

    ret = HostRndisInitUnion(usbNet, &retval);
    if (ret == HDF_ERR_MALLOC_FAIL) {
        HDF_LOGE("%{public}s:%{public}d HostRndisInitUnion failed", __func__, __LINE__);
        return ret;
    } else if (ret == HDF_DEV_ERR_OP) {
        HDF_LOGE("%{public}s:%{public}d HostRndisInitUnion failed", __func__, __LINE__);
        OsalMemFree(g_u.buf);
        return ret;
    }

    HostRndisUpdateMtu(&usbNet, &retval);
    if (retval == HDF_ERR_INVALID_PARAM) {
        HDF_LOGE("%{public}s:%{public}d HostRndisUpdateMtu failed", __func__, __LINE__);
        goto ERR_HALT_FAILED_AND_RELEASE;
        return retval;
    }

    HostRndisSetmacAddr(&usbNet, &retval);
    if (retval == HDF_ERR_NOPERM) {
        HDF_LOGE("%{public}s:%{public}d HostRndisSetmacAddr failed", __func__, __LINE__);
        goto ERR_HALT_FAILED_AND_RELEASE;
        return retval;
    }

    ret = HostRndisEnableDataTransfers(usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d HostRndisEnableDataTransfers failed", __func__, __LINE__);
        goto ERR_HALT_FAILED_AND_RELEASE;
    }
    return ret;
ERR_HALT_FAILED_AND_RELEASE:
    memset_s(g_u.halt, sizeof(struct RndisHalt), 0, sizeof(struct RndisHalt));
    g_u.halt->msgType = CPU_TO_LE32(RNDIS_MSG_HALT);
    g_u.halt->msgLen = CPU_TO_LE32(sizeof(struct RndisHalt));
    (void)HostRndisCommand(usbNet, (void *)g_u.halt, CONTROL_BUFFER_SIZE);
    return HDF_FAILURE;
}

static void HostRndisUnbind(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT();
    struct RndisHalt *halt = OsalMemAlloc(sizeof(struct RndisHalt));

    memset_s(halt, sizeof(struct RndisHalt), 0, sizeof(struct RndisHalt));
    halt->msgType = CPU_TO_LE32(RNDIS_MSG_HALT);
    halt->msgLen  = CPU_TO_LE32(sizeof(struct RndisHalt));
    (void) HostRndisCommand(usbNet, (void *)halt, CONTROL_BUFFER_SIZE);
    OsalMemFree(halt);
}

static struct UsbnetHostDriverInfo g_hostRndisInfo = {
    .description    =    "rndis device",
    .bind           =    HostRndisBind,
    .unbind         =    HostRndisUnbind,
};

static int32_t HostRndisDriverDeviceDispatch(
    struct HdfDeviceIoClient *client, int32_t cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    return HDF_SUCCESS;
}

/* HdfDriverEntry implementations */
static int32_t HostRndisDriverBind(struct HdfDeviceObject *device)
{
    HARCH_INFO_PRINT("[-cbs-] HostRndisDriverBind begin !");
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct UsbnetHost *usbNet = (struct UsbnetHost *)OsalMemCalloc(sizeof(*usbNet));
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: Alloc  UsbnetHost memory failed", __func__);
        return HDF_FAILURE;
    }

    struct UsbPnpNotifyServiceInfo *info = NULL;
    info = (struct UsbPnpNotifyServiceInfo *)device->priv;
    if (info != NULL) {
        HARCH_INFO_PRINT("[-cbs-]bus:%{public}d+dev:%{public}d", info->busNum, info->devNum);
        HARCH_INFO_PRINT("[-cbs-]interfaceLength:%{public}d", info->interfaceLength);
        HARCH_INFO_PRINT("[-cbs-]curInterfaceNum:%{public}d", info->curInterfaceNumber);

        usbNet->busNum = info->busNum;
        usbNet->devAddr = info->devNum;
        usbNet->curInterfaceNumber = info->curInterfaceNumber;
    } else {
        HDF_LOGE("%{public}s:%{public}d info is NULL!", __func__, __LINE__);
        goto ERROR;
    }

    HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
    device->service = &(usbNet->service);
    if (device->service == NULL) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
    }

    device->service->Dispatch = HostRndisDriverDeviceDispatch;
    usbNet->deviceObject = device;

    /* here need to choose device driver */
    struct  UsbnetHostDriverInfo *driver = &g_hostRndisInfo;
    //function
    usbNet->driverInfo = driver;

    HARCH_INFO_PRINT("bind ok");
    return HDF_SUCCESS;
ERROR:
    OsalMemFree(usbNet);
    return HDF_SUCCESS;
}

static int32_t HostRndisDriverInit(struct HdfDeviceObject *device)
{
    HARCH_INFO_PRINT("[-cbs-] HostRndisDriverInit begin !");
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    int32_t ret = HDF_SUCCESS;

    struct UsbnetHost *usbNet = (struct UsbnetHost *)device->service;
    //net init
    ret = UsbnetHostProbe(usbNet);
    if (ret != HDF_SUCCESS) {
        HARCH_INFO_PRINT("[-cbs-] UsbnetHostProbe error !");
    }
    //usb init
    return ret;
}

static void HostRndisDriverRelease(struct HdfDeviceObject *device)
{
    HARCH_INFO_PRINT();
    struct UsbPnpNotifyServiceInfo *info = NULL;
    info = (struct UsbPnpNotifyServiceInfo *)device->priv;
    if (info != NULL) {
        HARCH_INFO_PRINT("bus:%{public}d+dev:%{public}d", info->busNum, info->devNum);
        HARCH_INFO_PRINT("interfaceLength:%{public}d", info->interfaceLength);
    }
    struct UsbnetHost *usbNet = (struct UsbnetHost *)device->service;
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: Alloc  UsbnetHost memory failed", __func__);
        return;
    }

    UsbnetHostRelease(usbNet);
    usbNet->driverInfo->unbind(usbNet);

    //free momory
    OsalMemFree(usbNet);
    return;
}

struct HdfDriverEntry g_hostRndisRawDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usbhost_rndis_rawapi",
    .Bind = HostRndisDriverBind,
    .Init = HostRndisDriverInit,
    .Release = HostRndisDriverRelease,
};
HDF_INIT(g_hostRndisRawDriverEntry);
