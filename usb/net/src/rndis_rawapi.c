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

#define HDF_LOG_TAG    USB_HOST_RNDIS_RAW_API

static int32_t UsbGetBulkEndpoint(struct UsbnetHost *usbNet, const struct UsbRawEndpointDescriptor *endPoint)
{
    if ((endPoint->endpointDescriptor.bEndpointAddress & USB_DDK_ENDPOINT_DIR_MASK) == USB_DDK_DIR_IN) {
        /* get bulk in endpoint */
        usbNet->dataInEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
        if (usbNet->dataInEp == NULL) {
            HDF_LOGE("%{public}s:%{public}d allocate dataInEp failed", __func__, __LINE__);
            return HDF_FAILURE;
        }
        usbNet->dataInEp->addr = endPoint->endpointDescriptor.bEndpointAddress;
        usbNet->dataInEp->interval = endPoint->endpointDescriptor.bInterval;
        usbNet->dataInEp->maxPacketSize = endPoint->endpointDescriptor.wMaxPacketSize;
        HARCH_INFO_PRINT("usbNet->dataInEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
                usbNet->dataInEp->addr, usbNet->dataInEp->interval, usbNet->dataInEp->maxPacketSize);
    } else {
        /* get bulk out endpoint */
        usbNet->dataOutEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
        if (usbNet->dataOutEp == NULL) {
            HDF_LOGE("%{public}s:%{public}d allocate dataOutEp failed", __func__, __LINE__);
            return HDF_FAILURE;
        }
        usbNet->dataOutEp->addr = endPoint->endpointDescriptor.bEndpointAddress;
        usbNet->dataOutEp->interval = endPoint->endpointDescriptor.bInterval;
        usbNet->dataOutEp->maxPacketSize = endPoint->endpointDescriptor.wMaxPacketSize;
        HARCH_INFO_PRINT("usbNet->dataOutEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
                usbNet->dataOutEp->addr, usbNet->dataOutEp->interval, usbNet->dataOutEp->maxPacketSize);
    }
    return HDF_SUCCESS;
}

static void UsbParseConfigDescriptorProcess(struct UsbnetHost *usbNet, 
                                                        const struct UsbRawInterface *interface, uint8_t interfaceIndex)
{
    uint8_t ifaceClass   = interface->altsetting->interfaceDescriptor.bInterfaceClass;
    uint8_t numEndpoints = interface->altsetting->interfaceDescriptor.bNumEndpoints;
    HARCH_INFO_PRINT("ifaceClass=%{public}d, numEndpoints=%{public}d", ifaceClass, numEndpoints); //import for ifaceClass
    switch (ifaceClass) {
        case USB_DDK_CLASS_WIRELESS_CONTROLLER: //USB_DDK_CLASS_COMM:
            usbNet->ctrlIface = interfaceIndex;
            HARCH_INFO_PRINT("ctrlInface:%{public}d", interfaceIndex);
            usbNet->statusEp = OsalMemAlloc(sizeof(struct UsbEndpoint));
            if (usbNet->statusEp == NULL) {
                HDF_LOGE("%{public}s:%{public}d allocate endpoint failed", __func__, __LINE__);
                break;
            }
            /* get the first endpoint by default */
            usbNet->statusEp->addr = interface->altsetting->endPoint[0].endpointDescriptor.bEndpointAddress;
            usbNet->statusEp->interval = interface->altsetting->endPoint[0].endpointDescriptor.bInterval;
            usbNet->statusEp->maxPacketSize = interface->altsetting->endPoint[0].endpointDescriptor.wMaxPacketSize;
            
            HARCH_INFO_PRINT("usbNet->statusEp=[addr:%{public}#x, interval:%{public}d, maxPacketSize:%{public}hu]",
                usbNet->statusEp->addr, usbNet->statusEp->interval, usbNet->statusEp->maxPacketSize);
            break;
        case USB_DDK_CLASS_CDC_DATA:
            usbNet->dataIface = interfaceIndex;
            HARCH_INFO_PRINT("dataIface:%{public}d", interfaceIndex);
            for (uint8_t j = 0; j < numEndpoints; j++) {
                const struct UsbRawEndpointDescriptor *endPoint = &interface->altsetting->endPoint[j];
                if (UsbGetBulkEndpoint(usbNet, endPoint) != HDF_SUCCESS) {
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

static int32_t UsbParseConfigDescriptor(struct UsbnetHost *usbNet)
{
    const struct UsbRawInterface *interface = usbNet->config->interface[0];
    //set 0 interface and 1 interface data endpoint and ctrl endpoint
    int32_t ret = UsbRawClaimInterface(usbNet->devHandle, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d claim interface failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("");
    UsbParseConfigDescriptorProcess(usbNet, interface, 0); 

    const struct UsbRawInterface *interface1 = usbNet->config->interface[1];
    ret = UsbRawClaimInterface(usbNet->devHandle, 1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d claim interface failed", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("");
    UsbParseConfigDescriptorProcess(usbNet, interface1, 1); 
    return HDF_SUCCESS;
}

/*
 * RNDIS indicate messages.
 */
static void HostRndisMsgIndicate(struct UsbnetHost *usbNet, struct rndis_indicate *msg,
                int buflen)
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
int32_t HostRndisCommand(struct UsbnetHost *usbNet, struct rndis_msg_hdr *buf, int buflen)
{
    HARCH_INFO_PRINT("begin");
    uint32_t msg_type = CPU_TO_LE32(buf->msg_type);
    uint32_t xid = 0;
    
    /* Issue the request; xid is unique, don't bother byteswapping it */
    if (msg_type != RNDIS_MSG_HALT && msg_type != RNDIS_MSG_RESET) {
        xid = usbNet->xid++;
        if (!xid) {
            xid = usbNet->xid++;
        }
        buf->request_id = (__force __le32) xid;
    }
    HARCH_INFO_PRINT("msg_type= %{public}d, xid = %{public}d",msg_type, xid);
    
    int retval = UsbnetHostWriteCmdSync(usbNet,USB_DDK_CDC_SEND_ENCAPSULATED_COMMAND,
        USB_DDK_DIR_OUT|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE, 0, usbNet->curInterfaceNumber,
        buf, CPU_TO_LE32(buf->msg_len));
        
    UsbnetWriteLog((char *)buf, CPU_TO_LE32(buf->msg_len), 0);
    HARCH_INFO_PRINT("retval = %{public}d",retval);
    if (retval < 0 || xid == 0) {
        return retval;
    }
    HARCH_INFO_PRINT("rndis xid %{public}d\n", xid);

    uint32_t count = 0;
    uint32_t request_id, msg_len, rsp, status;
    /* Poll the control channel; the request probably completed immediately */
    rsp = CPU_TO_LE32(buf->msg_type) | RNDIS_MSG_COMPLETION;
    for (count = 0; count < 10; count++) {
        HARCH_INFO_PRINT("count = %{public}d, buflen = %{public}d", count, buflen);
        memset(buf, 0, CONTROL_BUFFER_SIZE);
        retval= UsbnetHostWriteCmdSync(usbNet,USB_DDK_CDC_GET_ENCAPSULATED_RESPONSE,
                USB_DDK_DIR_IN|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE, 0, usbNet->curInterfaceNumber,
                buf, buflen);

        HARCH_INFO_PRINT("retval = %{public}d",retval);
        UsbnetWriteLog((char *)buf, buflen, 0);
        if (retval > 8) {
            msg_type = CPU_TO_LE32(buf->msg_type);
            msg_len = CPU_TO_LE32(buf->msg_len);
            status = CPU_TO_LE32(buf->status);
            request_id =  (__force uint32_t)buf->request_id;
            HARCH_INFO_PRINT("rndis reply msg_type = %{public}x,  msg_len = %{public}x, status = %{public}x, request_id = %{public}x", 
                    msg_type, msg_len, status, request_id);

            if (msg_type == rsp) {
                if (request_id == xid) {
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
                HARCH_INFO_PRINT("rndis reply id %{public}d expected %{public}d\n", request_id, xid);
                /* then likely retry */
            } else {
                HARCH_INFO_PRINT("unexpected rndis msg %{public}08x len %{public}d\n", CPU_TO_LE32(buf->msg_type), msg_len);
                switch (msg_type) {
                    /* fault/event */
                    case RNDIS_MSG_INDICATE:
                        HostRndisMsgIndicate(usbNet, (void *)buf, buflen);
                        break;
                    case RNDIS_MSG_KEEPALIVE: {
                            /* ping */
                            struct rndis_keepalive_c *msg = (void *)buf;
                            msg->msg_type = CPU_TO_LE32(RNDIS_MSG_KEEPALIVE_C);
                            msg->msg_len = CPU_TO_LE32(sizeof *msg);
                            msg->status = CPU_TO_LE32(RNDIS_STATUS_SUCCESS);
                            retval= UsbnetHostWriteCmdSync(usbNet,USB_DDK_CDC_SEND_ENCAPSULATED_COMMAND,
                                            USB_DDK_DIR_OUT|USB_DDK_TYPE_CLASS|USB_DDK_RECIP_INTERFACE, 0, usbNet->curInterfaceNumber,
                                            msg, sizeof (*msg));
                            HARCH_INFO_PRINT("retval = %{public}d",retval);
                            if (retval < 0) {
                                HARCH_INFO_PRINT("rndis keepalive err %{public}d\n", retval);
                            }
                        }
                        break;
                    default:
                        HARCH_INFO_PRINT("unexpected rndis msg %{public}08x len %{public}d\n", CPU_TO_LE32(buf->msg_type), msg_len);
                        break;
                }
            }
        } else {
            /* device probably issued a protocol stall; ignore */
            HARCH_INFO_PRINT("rndis response error = %{public}d", retval);
        }
        OsalMSleep(40);
    }
    HARCH_INFO_PRINT("rndis response timeout");
    return HDF_ERR_TIMEOUT;
}


/*
 * rndis_query:
 *
 * Performs a query for @oid along with 0 or more bytes of payload as
 * specified by @in_len. If @reply_len is not set to -1 then the reply
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
int32_t HostRndisQuery(struct UsbnetHost *usbNet, void *buf, uint32_t oid, uint32_t in_len, void **reply, int *reply_len)
{
    HARCH_INFO_PRINT("begin");
    int retval;
    union {
        void *buf;
        struct rndis_msg_hdr *header;
        struct rndis_query *get;
        struct rndis_query_c *get_c;
    } u;
    uint32_t off, len;
    u.buf = buf;
    memset(u.get, 0, sizeof *u.get + in_len);
    u.get->msg_type = CPU_TO_LE32(RNDIS_MSG_QUERY);
    u.get->msg_len  = CPU_TO_LE32(sizeof *u.get + in_len);
    u.get->oid = CPU_TO_LE32(oid);
    u.get->len = CPU_TO_LE32(in_len);
    u.get->offset = CPU_TO_LE32(20);

    retval = HostRndisCommand(usbNet, u.header, CONTROL_BUFFER_SIZE);
    HARCH_INFO_PRINT("retval = %{public}d",retval);
    HARCH_INFO_PRINT("RNDIS_MSG_QUERY(0x%{public}08x) %{public}d\n", oid, retval);
    if (retval < 0) {
        HDF_LOGE("RNDIS_MSG_QUERY(0x%{public}08x) failed, %{public}d\n", oid, retval);
        return retval;
    }

    off = CPU_TO_LE32(u.get_c->offset);
    len = CPU_TO_LE32(u.get_c->len);

    HARCH_INFO_PRINT("off = %{public}d, len = %{public}d, retval = %{public}d", off, len, retval);

    if ((off > CONTROL_BUFFER_SIZE - 8) || (len > CONTROL_BUFFER_SIZE - 8 - off)) {
        goto response_error;
    }

    if (*reply_len != -1 && len != *reply_len) {
        goto response_error;
    }

    *reply = (unsigned char *) &u.get_c->request_id + off;
    *reply_len = len;

    HARCH_INFO_PRINT("*reply_len = %{public}d, retval = %{public}d", len, retval);
    return retval;

response_error:
    HDF_LOGE("RNDIS_MSG_QUERY(0x%{public}08x) invalid response - off %{public}d len %{public}d\n", oid, off, len);

    return -EDOM;
}

/* function
    1.get usb endpoints info
    2.init usb device 
    3.get usb device adrress and status
    4.set usb device work
*/
static int32_t HostRndisBind(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT("begin");
    int retval = 0;
    //get data endpoints and control endpoints
    int32_t ret = UsbParseConfigDescriptor(usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbParseConfigDescriptor failed", __func__, __LINE__);
        ret = HDF_FAILURE;
        goto ERR_PARSE_DESC;
    }

    union {
        void *buf;
        struct rndis_msg_hdr *header;
        struct rndis_init *init;
        struct rndis_init_c *init_c;
        struct rndis_query *get;
        struct rndis_query_c *get_c;
        struct rndis_set *set;
        struct rndis_set_c *set_c;
        struct rndis_halt *halt;
    } u;

    u.buf = OsalMemAlloc(CONTROL_BUFFER_SIZE);
    if (!u.buf) {
        HDF_LOGE( "u.buf can't be 0\n");
        retval = HDF_ERR_MALLOC_FAIL;
        goto ERR_PARSE_DESC;
    }

    u.init->msg_type = CPU_TO_LE32(RNDIS_MSG_INIT);
    u.init->msg_len  = CPU_TO_LE32(sizeof *u.init);
    u.init->major_version = CPU_TO_LE32(1);
    u.init->minor_version = CPU_TO_LE32(0);
   
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
    usbNet->net.hardHeaderLen += sizeof (struct rndis_data_hdr); //net header
    usbNet->net.hardMtu = usbNet->net.mtu + usbNet->net.hardHeaderLen;
    HARCH_INFO_PRINT("hardHeaderLen = %{public}d, hardMtu = %{public}d\n", usbNet->net.hardHeaderLen, usbNet->net.hardMtu);
    //
    usbNet->net.maxpacket = usbNet->dataOutEp->maxPacketSize;
    HARCH_INFO_PRINT("maxpacket = %{public}d\n", usbNet->net.maxpacket);
    if (usbNet->net.maxpacket == 0) {
        HDF_LOGE( "usbNet->maxpacket can't be 0\n");
        retval = HDF_ERR_INVALID_PARAM;
        goto ERR_RELEASE_BUF;
    }
    
    usbNet->net.rxUrbSize = usbNet->net.hardMtu + (usbNet->net.maxpacket + 1);
    HARCH_INFO_PRINT("rxUrbSize = %{public}d\n", usbNet->net.rxUrbSize);
    usbNet->net.rxUrbSize &= ~(usbNet->net.maxpacket - 1);

    HARCH_INFO_PRINT("rxUrbSize = %{public}d\n", usbNet->net.rxUrbSize);
    u.init->max_transfer_size = CPU_TO_LE32(usbNet->net.rxUrbSize);

    retval = HostRndisCommand(usbNet, u.header, CONTROL_BUFFER_SIZE);
    if (retval < 0) {
        /* it might not even be an RNDIS device!! */
        HARCH_INFO_PRINT("RNDIS init failed, %{public}d", retval);
        HDF_LOGE("RNDIS init failed, %{public}d", retval);
        ret = HDF_FAILURE;
        goto ERR_RELEASE_BUF;
    }

    uint32_t tmp = CPU_TO_LE32(u.init_c->max_transfer_size);
    if (tmp < usbNet->net.hardMtu) {
        if (tmp <= usbNet->net.hardHeaderLen) {
            HARCH_INFO_PRINT("RNDIS init failed, %{public}d", retval);
            HDF_LOGE("usbNet can't take %{public}u byte packets (max %{public}u)\n", usbNet->net.hardMtu, tmp);
            retval = HDF_ERR_INVALID_PARAM;
            goto ERR_HALT_FAILED_AND_RELEASE;
        }
        HARCH_INFO_PRINT("usbNet can't take %{public}u byte packets (max %{public}u) adjusting MTU to %{public}u\n", usbNet->net.hardMtu, tmp, tmp - usbNet->net.hardHeaderLen);
        HDF_LOGW("usbNet can't take %{public}u byte packets (max %{public}u) adjusting MTU to %{public}u\n", usbNet->net.hardMtu, tmp, tmp - usbNet->net.hardHeaderLen);
        usbNet->net.hardMtu = tmp;
        usbNet->net.mtu = usbNet->net.hardMtu - usbNet->net.hardHeaderLen;
    }

    HARCH_INFO_PRINT(
        "hard mtu %{public}u (%{public}u from usbNet), rx buflen %{public}zu, align %{public}d\n",
        usbNet->net.hardMtu, tmp, usbNet->net.rxUrbSize,
        1 << CPU_TO_LE32(u.init_c->packet_alignment));
    
    /* Check physical medium */
    __le32 *phym = NULL;
    __le32    phym_unspec;
    int reply_len = sizeof (*phym);
    retval = HostRndisQuery(usbNet, u.buf,
                 RNDIS_OID_GEN_PHYSICAL_MEDIUM,
                 reply_len, (void **)&phym, &reply_len);

    if (retval != 0 || !phym) {
        /* OID is optional so don't fail here. */
        phym_unspec = CPU_TO_LE32(RNDIS_PHYSICAL_MEDIUM_UNSPECIFIED);
        phym = &phym_unspec;
    }

    if ((usbNet->flags & FLAG_RNDIS_PHYM_WIRELESS) &&
        CPU_TO_LE32(*phym) != RNDIS_PHYSICAL_MEDIUM_WIRELESS_LAN) {
        HDF_LOGE("driver requires wireless physical medium, but device is not\n");
        retval = HDF_ERR_NOPERM;
        goto ERR_HALT_FAILED_AND_RELEASE;
    }

    if ((usbNet->flags & FLAG_RNDIS_PHYM_NOT_WIRELESS) &&
        CPU_TO_LE32(*phym) == RNDIS_PHYSICAL_MEDIUM_WIRELESS_LAN) {
        HDF_LOGE("driver requires non-wireless physical medium, but device is wireless\n");
        retval = HDF_ERR_NOPERM;
        goto ERR_HALT_FAILED_AND_RELEASE;
    }

    /* Get designated host ethernet address */
    reply_len = MAC_ADDR_SIZE;
    unsigned char *bp;
    retval = HostRndisQuery(usbNet, u.buf,RNDIS_OID_802_3_PERMANENT_ADDRESS, 
                            48, (void **) &bp, &reply_len);
    if (retval< 0) {
        HDF_LOGE("rndis get ethaddr, %{public}d\n", retval);
        retval = HDF_ERR_NOPERM;
        goto ERR_HALT_FAILED_AND_RELEASE;
    }

    HARCH_INFO_PRINT("bp 1= %{public}x",bp[0]);
    HARCH_INFO_PRINT("bp 2= %{public}x",bp[1]);
    HARCH_INFO_PRINT("bp 3= %{public}x",bp[2]);
    HARCH_INFO_PRINT("bp 4= %{public}x",bp[3]);
    HARCH_INFO_PRINT("bp 5= %{public}x",bp[4]);
    HARCH_INFO_PRINT("bp 6= %{public}x",bp[5]);

    if (bp[0] & 0x02) {
        HARCH_INFO_PRINT("not GetmacAddr");
        usbNet->net.isGetmacAddr = 0;
        memset(usbNet->net.macAddr,0,sizeof(usbNet->net.macAddr));
    } else {
        HARCH_INFO_PRINT("GetmacAddr");
        usbNet->net.isGetmacAddr = 1;
        etherAddrCopy(usbNet->net.macAddr, bp);
    }

    /* set a nonzero filter to enable data transfers */
    memset(u.set, 0, sizeof *u.set);
    u.set->msg_type = CPU_TO_LE32(RNDIS_MSG_SET);
    u.set->msg_len = CPU_TO_LE32(4 + sizeof *u.set);
    u.set->oid = CPU_TO_LE32(RNDIS_OID_GEN_CURRENT_PACKET_FILTER);
    u.set->len = CPU_TO_LE32(4);
    u.set->offset = CPU_TO_LE32((sizeof *u.set) - 8);
    *(__le32 *)(u.buf + sizeof *u.set) = CPU_TO_LE32(RNDIS_DEFAULT_FILTER);
    retval = HostRndisCommand(usbNet, u.header, CONTROL_BUFFER_SIZE);
    if (retval < 0) {
        HDF_LOGE("rndis set packet filter, %{public}d", retval);
        goto ERR_HALT_FAILED_AND_RELEASE;
    }

    OsalMemFree(u.buf);
    return  HDF_SUCCESS;

ERR_HALT_FAILED_AND_RELEASE:
    memset(u.halt, 0, sizeof *u.halt);
    u.halt->msg_type = CPU_TO_LE32(RNDIS_MSG_HALT);
    u.halt->msg_len = CPU_TO_LE32(sizeof *u.halt);
    (void) HostRndisCommand(usbNet,(void *)u.halt, CONTROL_BUFFER_SIZE);
ERR_RELEASE_BUF:
    OsalMemFree(u.buf);
ERR_PARSE_DESC:
    UsbRawFreeConfigDescriptor(usbNet->config);
    usbNet->config = NULL;
    return HDF_FAILURE;
}

void HostRndisUnbind(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT();
    struct rndis_halt *halt = OsalMemAlloc(sizeof(struct rndis_halt));

    memset(halt, 0, sizeof *halt);
    halt->msg_type = CPU_TO_LE32(RNDIS_MSG_HALT);
    halt->msg_len  = CPU_TO_LE32(sizeof *halt);
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

    /*here need to choose device driver*/
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
