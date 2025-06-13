/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_LIBUSB_ADAPTER_H
#define OHOS_LIBUSB_ADAPTER_H

#include <memory>
#include <mutex>
#include <thread>
#include <list>
#include <map>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <libusb.h>

#include "libusb_sa_subscriber.h"
#include "v1_2/iusb_interface.h"
#include "v2_0/iusb_host_interface.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
struct SyncTranfer {
    int length;
    int *transferred;
    unsigned int timeout;
};
struct SendRequestAshmemParameter {
    int32_t ashmemFd;
    uint32_t ashmemSize;
};

struct LibusbAsyncTransfer {
    explicit LibusbAsyncTransfer(uint32_t numOfIsoPackage)
    {
        transferRef = libusb_alloc_transfer(numOfIsoPackage);
        ashmemRef = nullptr;
    }

    ~LibusbAsyncTransfer()
    {
        if (transferRef != nullptr) {
            libusb_free_transfer(transferRef);
            transferRef = nullptr;
        }
        ashmemRef = nullptr;
        cbRef = nullptr;
    }

    libusb_transfer *transferRef;
    sptr<Ashmem> ashmemRef;
    sptr<V1_2::IUsbdTransferCallback> cbRef = nullptr;
    int32_t busNum = 0;
    int32_t devAddr = 0;
    uint64_t userData = 0;
};

struct LibusbAsyncWrapper {
    std::list<LibusbAsyncTransfer *> transferList;
    std::mutex transferLock;
};

struct LibusbAsyncManager {
    std::vector<std::pair<UsbDev, LibusbAsyncWrapper*>> transferVec;
    std::mutex transferVecLock;
};

struct DeviceInfo {
    uint64_t deviceId;
    uint16_t vendorId;
};

struct LibusbBulkTransfer {
    explicit LibusbBulkTransfer()
    {
        bulkTransferRef = libusb_alloc_transfer(0);
        buikAshmemRef = nullptr;
        bulkCbRef = nullptr;
    }

    ~LibusbBulkTransfer()
    {
        if (bulkTransferRef != nullptr) {
            libusb_free_transfer(bulkTransferRef);
            bulkTransferRef = nullptr;
        }
        buikAshmemRef = nullptr;
        bulkCbRef = nullptr;
    }

    libusb_transfer *bulkTransferRef;
    sptr<Ashmem> buikAshmemRef;
    sptr<V2_0::IUsbdBulkCallback> bulkCbRef;
    int32_t busNum = 0;
    int32_t devAddr = 0;
    bool isTransferring {false};
};

struct LibusbBulkWrapper {
    std::list<LibusbBulkTransfer *> bulkTransferList;
    std::mutex bulkTransferLock;
};

struct LibusbBulkManager {
    std::vector<std::pair<UsbDev, LibusbBulkWrapper*>> bulktransferVec;
    std::mutex bulkTransferVecLock;
};

struct HotplugInfo {
public:
    HotplugInfo() : subscriberPtr(nullptr){};
    HotplugInfo(OHOS::HDI::Usb::V2_0::USBDeviceInfo &info, sptr<V2_0::IUsbdSubscriber> subscriber)
        : hotplugInfo(info),
        subscriberPtr(subscriber) {};

    OHOS::HDI::Usb::V2_0::USBDeviceInfo hotplugInfo;
    sptr<V2_0::IUsbdSubscriber> subscriberPtr;
};

class HotplugEventPorcess {
public:
    static std::shared_ptr<HotplugEventPorcess> GetInstance();
    void AddHotplugTask(OHOS::HDI::Usb::V2_0::USBDeviceInfo &info,
        sptr<V2_0::IUsbdSubscriber> subscriber = nullptr);
    int32_t SetSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber);
    int32_t RemoveSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber);
    size_t GetSubscriberSize();
    ~HotplugEventPorcess();
    HotplugEventPorcess();
private:
    std::queue<HotplugInfo> hotplugEventQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::atomic<int32_t> activeThreads_;
    bool shutdown_;
    std::list<sptr<V2_0::IUsbdSubscriber>> subscribers_;
    static std::shared_ptr<HotplugEventPorcess> instance_;
    static std::mutex mtx_;
    void OnProcessHotplugEvent();
};

class LibusbAdapter {
public:
    LibusbAdapter();
    ~LibusbAdapter();
    int32_t OpenDevice(const UsbDev &dev);
    int32_t CloseDevice(const UsbDev &dev);
    int32_t ResetDevice(const UsbDev &dev);
    int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
    int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd);
    int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
    int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
    int32_t ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
    int32_t BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
    int32_t BulkTransferReadwithLength(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, int32_t length,
        std::vector<uint8_t> &data);
    int32_t BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
        const std::vector<uint8_t> &data);
    int32_t IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
    int32_t IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
        const std::vector<uint8_t> &data);
    int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
    int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
    int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
    int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
    int32_t InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
    int32_t InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
        const std::vector<uint8_t> &data);
    int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
    int32_t ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force);
    int32_t ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
    int32_t ControlTransferWrite(const UsbDev &dev, const UsbCtrlTransfer &ctrl, const std::vector<uint8_t> &data);
    int32_t ControlTransferReadwithLength(const UsbDev &dev, const UsbCtrlTransferParams &ctrlParams,
        std::vector<uint8_t> &data);
    int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
    int32_t GetDeviceSpeed(const UsbDev &dev, uint8_t &speed);
    int32_t GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool &unactivated);
    int32_t SendPipeRequestWithAshmem(const UsbDev &dev, unsigned char endpointAddr,
        SendRequestAshmemParameter sendRequestAshmemParameter, uint32_t &transferredLength, unsigned int timeout);
    int32_t SendPipeRequest(const UsbDev &dev, unsigned char endpointAddr, uint32_t size,
        uint32_t &transferedLength, unsigned int timeout);
    int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
    int32_t GetCurrentInterfaceSetting(const UsbDev &dev, uint8_t &settingIndex);
    int32_t GetDeviceMemMapFd(const UsbDev &dev, int &fd);
    int32_t SetSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber);
    int32_t RemoveSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber);
    void ReportUsbdRecognitionFailSysEvent(const std::string &operationType, int32_t code,
        const std::string &failDescription, libusb_device *device = nullptr);

    /* Async Transfer */
    int32_t AsyncSubmitTransfer(const UsbDev &dev, const V1_2::USBTransferInfo &info,
        const sptr<V1_2::IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
    int32_t AsyncCancelTransfer(const UsbDev &dev, const int32_t endpoint);
    int32_t GetDevices(std::vector<struct DeviceInfo> &devices);

    /* Bulk Transfer */
    int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem);
    int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem);
    int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
    int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<V2_0::IUsbdBulkCallback> &cb);
    int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe);

    int32_t SetLoadUsbSaSubscriber(sptr<V1_2::LibUsbSaSubscriber> libUsbSaSubscriber);
    static std::shared_ptr<LibusbAdapter> GetInstance();

private:
    int32_t LibUSBInit();
    void LibUSBExit();
    void GetCurrentDeviceList(libusb_context *ctx, sptr<V2_0::IUsbdSubscriber> subscriber);
    void GetCurrentDevList(libusb_context *ctx, sptr<V1_2::LibUsbSaSubscriber> libUsbSaSubscriber);
    int32_t GetUsbDevice(const UsbDev &dev, libusb_device **device);
    int32_t FindHandleByDev(const UsbDev &dev, libusb_device_handle **handle);
    void DeleteSettingsMap(libusb_device_handle* handle);
    int32_t DoControlTransfer(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
    int32_t ReadDescriptors(int32_t fd, void **descriptors, size_t &descriptorsLength);
    int32_t GetUsbDevicePath(const UsbDev &dev, char *pathBuf, size_t length);
    void *AdapterRealloc(void *ptr, size_t oldSize, size_t newSize);
    void *AllocateUsbDescriptorsMemory(size_t size);
    void FreeUsbDescriptorsMemory(void *mem);
    int32_t GetConfigDescriptor(libusb_device *dev, uint8_t descId, std::vector<uint8_t> &descriptor);
    int32_t ProcessInterfaceDescriptors(const libusb_interface *iface, std::vector<uint8_t> &descriptor,
        size_t &currentOffset);
    struct libusb_config_descriptor* FindConfigDescriptorById(libusb_device *dev, uint8_t descId);
    void ProcessExtraData(std::vector<uint8_t> &descriptor, size_t &currentOffset, const unsigned char *extra,
        int32_t extraLength);
    int32_t GetEndpointDesc(const UsbDev &dev, const UsbPipe &pipe, libusb_endpoint_descriptor **endpoint_desc,
        libusb_device_handle** deviceHandle);
    int32_t DoSyncPipeTranfer(libusb_device_handle *dev_handle, unsigned char endpoint,
        unsigned char *buffer, SyncTranfer &syncTranfer);
    unsigned char *GetMmapBufferByFd(int32_t fd, size_t len);
    unsigned char *GetMmapFdAndBuffer(uint8_t busNumber, uint8_t busAddress, int32_t &fd, size_t len);
    int32_t CloseMmapBuffer(void *mmapBuf, size_t length);
    bool CheckDeviceAndConfiguration(libusb_device_handle *handle);
    int32_t GetCurrentConfiguration(libusb_device_handle *handle, int32_t &currentConfig);
    int32_t RemoveInterfaceFromMap(const UsbDev &dev, libusb_device_handle *devHandle, uint8_t interfaceId);
    bool IsInterfaceIdByUsbDev(const UsbDev &dev, const uint8_t intfId);
    int32_t DetachDevice(const UsbDev &dev);
    /* Async Transfer */
    void TransferInit(const UsbDev &dev);
    void TransferRelease(const UsbDev &dev);
    uint8_t *AllocAsyncBuffer(const V1_2::USBTransferInfo &info, const sptr<Ashmem> &ashmem);
    LibusbAsyncTransfer *CreateAsyncTransfer(const UsbDev &dev, const V1_2::USBTransferInfo &info,
        const sptr<Ashmem> &ashmem, const sptr<V1_2::IUsbdTransferCallback> &cb);
    int32_t FillAndSubmitTransfer(LibusbAsyncTransfer *asyncTransfer, libusb_device_handle *devHandle,
        unsigned char *buffer, const V1_2::USBTransferInfo &info);
    void DeleteAsyncDevRequest(const UsbDev &dev);
    void ClearAsyncTranfer(LibusbAsyncWrapper *asyncWrapper);
    void LibusbEventHandling();
    static LibusbAsyncWrapper *GetAsyncWrapper(const UsbDev &dev);
    static void HandleAsyncFailure(struct libusb_transfer *transfer);
    static void AddTransferToList(LibusbAsyncTransfer *asyncTransfer);
    static void DeleteTransferFromList(LibusbAsyncTransfer *asyncTransfer);
    static void FeedbackToBase(struct libusb_transfer *transfer);
    static void ParseIsoPacketDesc(libusb_transfer *transfer, std::vector<V1_2::UsbIsoPacketDescriptor> &isoPkgDescs);
    static int32_t ReadAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer);
    static int32_t WriteAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer);
    static void LIBUSB_CALL HandleAsyncResult(struct libusb_transfer *transfer);

    /* Bulk Transfer */
    static int32_t BulkReadAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer);
    static int32_t BulkWriteAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer);
    uint8_t *AllocBulkBuffer(const UsbPipe &pipe, const int32_t &length, const sptr<Ashmem> &ashmem);
    static void DeleteBulkTransferFromList(LibusbBulkTransfer *bulkTransfer);
    static void HandleBulkFail(struct libusb_transfer *transfer);
    static void BulkFeedbackToBase(struct libusb_transfer *transfer);
    static void LIBUSB_CALL HandleBulkResult(struct libusb_transfer *transfer);
    void BulkTransferInit(const UsbDev &dev);
    void BulkTransferRelease(const UsbDev &dev);
    void DeleteBulkDevRequest(const UsbDev &dev);
    void ClearBulkTranfer(LibusbBulkWrapper *bulkWrapper);
    static LibusbBulkWrapper *GetBulkWrapper(const UsbDev &dev);
    LibusbBulkTransfer *FindBulkTransfer(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem);

    static int HotplugCallback(libusb_context* ctx, libusb_device* device,
        libusb_hotplug_event event, void* user_data);
    static int LoadUsbSaCallback(libusb_context* ctx, libusb_device* device,
        libusb_hotplug_event event, void* user_data);
private:
    std::atomic<bool> isRunning;
    std::thread eventThread;
    libusb_hotplug_callback_handle hotplug_handle_ = 0;
    static sptr<V1_2::LibUsbSaSubscriber> libUsbSaSubscriber_;
};
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_LIBUSB_ADAPTER_H
