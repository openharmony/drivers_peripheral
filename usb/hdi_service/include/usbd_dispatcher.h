/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_USB_V1_2_USBD_DISPATCHER_H
#define OHOS_HDI_USB_V1_2_USBD_DISPATCHER_H

#include "usbd.h"

#define HDF_LOG_TAG Usbd

#define MAX_BUFF_SIZE         16384
#define MAX_CONTROL_BUFF_SIZE 1024
#define READ_BUF_SIZE         8192

#define USB_CTRL_SET_TIMEOUT         5000
#define GET_STRING_SET_TIMEOUT       50
#define USB_PIPE_DIR_OFFSET          7
#define CHARFORMAT                   8
#define USB_REUQEST_SLEEP_TIME       100
#define USB_MAX_DESCRIPTOR_SIZE      256
#define USB_BULK_CALLBACK_SLEEP_TIME 500
#define USB_BULK_CANCEL_SLEEP_TIME   1000

#define OPEN_SLEPP_TIME          1
#define SUBMIT_SLEEP_TIME        1
#define USBD_ASYNC_GETENODE_TIME 1
#define USBD_ASYNC_GETENODE_TRY  3

#define POS_STEP 3

#define MULTIPLE   3

#define USB_RECIP_MASK          0x1F
#define ENDPOINT_DIRECTION_MASK 0x1
#define CMD_TYPE_MASK           0x3

#define MAX_REQUESTASYNC_NUM 20

constexpr int32_t CMD_OFFSET_5 = 5;
constexpr int32_t DIRECTION_OFFSET_7 = 7;
constexpr int32_t TYPE_OFFSET_8 = 8;

enum UsbdReqNodeStatus {
    USBD_REQNODE_INIT,
    USBD_REQNODE_NOUSE,
    USBD_REQNODE_USE,
    USBD_REQNODE_OTHER,
};

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
class UsbImpl;
class UsbdDispatcher {
public:
    static int32_t UsbdAllocFifo(DataFifo *fifo, uint32_t size);
    static void UsbdFreeFifo(DataFifo *fifo);
    static void UsbdReadCallback(UsbRequest *req);
    static void UsbdWriteCallback(UsbRequest *req);
    static int32_t UsbControlSetUp(UsbControlParams *controlParams, UsbControlRequest *controlReq);
    static UsbInterface *GetUsbInterfaceById(const HostDevice *dev, uint8_t interfaceIndex);
    static int32_t GetInterfacePipe(
        const HostDevice *dev, UsbInterface *interface, uint8_t pipeAddr, UsbPipeInfo *pipe);
    static int32_t GetPipe(const HostDevice *dev, uint8_t interfaceId, uint8_t pipeId, UsbPipeInfo *pipe);
    static void UsbdFreeCtrlPipe(HostDevice *dev);
    static int32_t UsbdGetCtrlPipe(HostDevice *dev);
    static UsbdRequestSync *UsbdFindRequestSync(HostDevice *port, uint8_t interfaceId, uint8_t pipeAddr);
    static UsbdRequestSync *UsbdRequestSyncAlloc(void);
    static void UsbRequestParamsWSyncInit(UsbRequestParams *params, int32_t timeout, const UsbPipeInfo *pipe);
    static int32_t UsbdRequestSyncInit(
        HostDevice *port, UsbInterfaceHandle *ifHandle, UsbPipeInfo *pipe, UsbdRequestSync *requestSync);
    static int32_t UsbdRequestSyncInitwithLength(HostDevice *port, UsbInterfaceHandle *ifHandle,
        UsbPipeInfo *pipe, int32_t length, UsbdRequestSync *requestSync);
    static int32_t UsbdRequestSyncRelease(UsbdRequestSync *requestSync);
    static void UsbRequestParamsInit(UsbRequestParams *params, int32_t timeout);
    static int32_t CtrlTranParamGetReqType(HdfSBuf *data, UsbControlParams *pCtrParams, uint32_t requestType);
    static int32_t CtrlTransferParamInit(HdfSBuf *data, UsbControlParams *pCtrParams, int32_t *timeout);
    static void UsbdReleaseInterfaces(HostDevice *dev);
    static void UsbdCloseInterfaces(HostDevice *dev);
    static int32_t UsbdOpenInterfaces(HostDevice *dev);
    static void RemoveDevFromService(UsbImpl *service, HostDevice *port);
    static int32_t UsbdClaimInterfaces(HostDevice *dev);
    static int32_t ReturnGetPipes(int32_t ret, HostDevice *dev);
    static int32_t ReturnOpenInterfaces(int32_t ret, HostDevice *dev);
    static int32_t ReturnClainInterfaces(int32_t ret, HostDevice *dev);
    static int32_t UsbdInit(HostDevice *dev);
    static int32_t UsbdRequestASyncRelease(UsbdRequestASync *request);
    static int32_t UsbdBulkASyncReqRelease(UsbdBulkASyncReqList *list);
    static int32_t UsbdBulkASyncListRelease(UsbdBulkASyncList *list);
    static void UsbdRelease(HostDevice *dev);
    static int32_t UsbdMallocAndFill(uint8_t *&dataAddr, const std::vector<uint8_t> &data);
    static int32_t FillReqAyncParams(
        UsbdRequestASync *userData, UsbPipeInfo *pipe,
        UsbRequestParams *params, const uint8_t *buffer, uint32_t length);
    static UsbdRequestASync *UsbdRequestASyncAlloc(void);
    static int32_t UsbdRequestASyncInit(
        HostDevice *port, UsbInterfaceHandle *ifHandle, UsbPipeInfo *pipe, UsbdRequestASync *request);
    static UsbdRequestASync *UsbdRequestASyncCreatAndInsert(HostDevice *port, uint8_t interfaceId, uint8_t pipeAddr);
    static int32_t HostDeviceInit(HostDevice *port);
    static int32_t HostDeviceCreate(HostDevice **port);
    static int32_t FunAttachDevice(HostDevice *port, HdfSBuf *data, HdfSBuf *reply);
    static int32_t UsbdDeviceCreateAndAttach(const sptr<UsbImpl> &service, uint8_t busNum, uint8_t devAddr);
    static int32_t FunDetachDevice(HostDevice *port, HdfSBuf *data);
    static int32_t UsbdDeviceDettach(UsbImpl *service, uint8_t busNum, uint8_t devAddr);
    static HostDevice *UsbdFindDevForBusNum(UsbImpl *service, uint8_t busNum);
    static int32_t UsbdRemoveBusDev(UsbImpl *service, uint8_t busNum, const sptr<IUsbdSubscriber> &subscriber);
    static int32_t UsbdBulkASyncReqInit(UsbdBulkASyncReqList *list, UsbdBulkASyncList *pList);
    static UsbdBulkASyncList *UsbdBulkASyncListAlloc(HostDevice *port, uint8_t ifId, uint8_t epId);
    static int32_t UsbdBulkASyncReqNodeSetNoUse(UsbdBulkASyncReqNode *db);
    static UsbdBulkASyncReqNode *UsbdBulkASyncReqGetENode(UsbdBulkASyncReqList *list);
    static int32_t UsbdBulkReadRemoteCallback(
        const sptr<IUsbdBulkCallback> &service, int32_t status, UsbdBufferHandle *handle);
    static int32_t UsbdBulkWriteRemoteCallback(
        const sptr<IUsbdBulkCallback> &service, int32_t status, UsbdBufferHandle *handle);
    static int32_t UsbdBulkASyncPutAsmData(UsbdBufferHandle *handle, uint8_t *buffer, uint32_t len);
    static int32_t UsbdBulkAsyncGetAsmData(UsbdBufferHandle *handle, UsbRequestParams *params, uint16_t maxPacketSize);
    static int32_t UsbdBulkAsyncGetAsmReqLen(UsbdBufferHandle *handle, uint32_t *reqLen, uint16_t maxPacketSize);
    static int32_t UsbdBulkASyncReqWriteAutoSubmit(UsbRequest *request);
    static int32_t UsbdBulkASyncReqReadAutoSubmit(UsbRequest *request);
    static void UsbdBulkASyncWriteCallbackAutoSubmit(UsbRequest *request);
    static void UsbdBulkASyncReadCallbackAutoSubmit(UsbRequest *request);
    static int32_t UsbdBulkASyncReqFillParams(UsbPipeInfo *pipe, UsbRequestParams *params, uint8_t *buffer);
    static int32_t UsbdBulkASyncReqWriteSubmit(UsbdBulkASyncReqNode *req);
    static int32_t UsbdBulkASyncReqReadSubmit(UsbdBulkASyncReqNode *db);
};
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V1_2_USBD_DISPATCHER_H
