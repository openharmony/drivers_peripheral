/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */
 
#ifndef HDF_USB_NET_MANAGE_H
#define HDF_USB_NET_MANAGE_H

#include "hdf_base.h"
#include "hdf_device_desc.h"


#define MAC_ADDR_SIZE 6
#define IFNAMSIZ 16

/* framing is CDC Ethernet, not writing ZLPs (hw issues), or optionally: */
#define FLAG_FRAMING_NC     0x0001          /* guard against device dropouts */
#define FLAG_FRAMING_GL     0x0002          /* genelink batches packets */
#define FLAG_FRAMING_Z      0x0004          /* zaurus adds a trailer */

#define HDF_FLAG_NO_SETINT    0x0010        /* device can't set_interface() */
#define HDF_FLAG_ETHER        0x0020        /* maybe use "eth%d" names */

#define FLAG_FRAMING_AX         0x0040        /* AX88772/178 packets */
#define FLAG_WLAN                0x0080        /* use "wlan%d" names */
#define FLAG_AVOID_UNLINK_URBS     0x0100        /* don't unlink urbs at usbnet_stop() */
#define FLAG_SEND_ZLP            0x0200        /* hw requires ZLPs are sent */
#define FLAG_WWAN                0x0400        /* use "wwan%d" names */

#define FLAG_LINK_INTR        0x0800        /* updates link (carrier) status */
#define HDF_FLAG_POINTTOPOINT     0x1000    /* possibly use "usb%d" names */

/*
 * Indicates to usbnet, that USB driver accumulates multiple IP packets.
 * Affects statistic (counters) and short packet handling.
 */
#define FLAG_MULTI_PACKET     0x2000
#define FLAG_RX_ASSEMBLE      0x4000    /* rx packets may span >1 frames */
#define FLAG_NOARP            0x8000    /* device can't do ARP */

enum UsbnetServiceCmd {
    USB_NET_REGISTER_NET,
    USB_NET_CLOSE_NET,
    USB_NET_SEND_DATA_TO_USB,
    USB_NET_RECIVE_DATA_FROM_USB,
    USB_NET_OPEN_USB,
    USB_NET_CLOSE_USB,
    USB_NET_UPDATE_FLAGS,
    USB_NET_UPDATE_MAXQLEN
};

struct UsbnetTransInfo {
    uint8_t isBindDevice;
    char name[IFNAMSIZ];                        /**< Network device name {@link IFNAMSIZ} */
    uint8_t isGetmacAddr;
    uint8_t macAddr[MAC_ADDR_SIZE];             /**< MAC address {@link MAC_ADDR_SIZE} */
    uint32_t flags;                             /**< Network port status */
    uint32_t mtu;                               /**< Maximum transmission unit */
    uint16_t hardHeaderLen;                     /**< Header length */
    uint8_t link;
    uint8_t needReset;
    uint32_t usbFlags;                        /**< usb device match flags */
    uint32_t rxUrbSize;    /* size for rx urbs */
    uint32_t hardMtu;    /* count any extra framing */
    uint32_t maxpacket;
    int txQlen;
};

#endif