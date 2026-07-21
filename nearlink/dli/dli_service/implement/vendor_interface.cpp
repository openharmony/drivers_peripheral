/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <thread>
#include <dlfcn.h>
#include <future>
#include <securec.h>
#include "common_timer_errors.h"
#include "nearlink_hdf_log.h"
#include "sle_address.h"
#include "sle_hal_constant.h"
#include "timer.h"
#include "h4_protocol.h"
#include "vendor_interface.h"
#include "parameters.h"
#include "thread_util.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
namespace V1_1 {

constexpr size_t DLI_PACKET_TYPE_SIZE = 1;
constexpr uint16_t DLI_SET_SLE_ADDR = 0x0405;
/* Define the preamble length for all DLI Commands. This is 2-bytes for opcode and 2 byte for length */
constexpr size_t DLIC_PREAMBLE_SIZE = 4;
/* Device address length */
constexpr int BD_ADDR_LEN = 6;
constexpr int OFFSET_EIGHT_BITS = 8;
constexpr int OFFSET_STATUS = 3;
constexpr size_t SLE_VENDOR_INVALID_DATA_LEN = 0;
constexpr int DLI_INTERFACE_CLOSED = 0;
constexpr int DLI_INTERFACE_OPENING = 1;
constexpr int DLI_INTERFACE_OPENED = 2;
constexpr int SET_ADDR_TIME_OUT_MS = 200;

struct InternalCommand {
    uint16_t cb;
    uint16_t opcode;
};

struct TaskConfig {
    pid_t pid;
    unsigned int value;
};

#define SET_VIP_PRIO 25
#define PERF_CTRL_MAGIC 'x'
#define PERF_CTRL_SET_VIP_PRIO \
	_IOW(PERF_CTRL_MAGIC, SET_VIP_PRIO, struct TaskConfig)

class VendorInterface::Impl {
public:
    bool Initialize(VendorInterface::InitializeCompleteCallback initializeCompleteCallback,
        const VendorInterface::ReceiveCallback &receiveCallback);
    void CleanUp();
    size_t SendPacket(const std::vector<uint8_t> &packet);
    void SetSleAddress(uint8_t *localSleAddr);
    uint8_t *TransformAddress(uint8_t *addr);
    void OnEventReceived(const std::vector<uint8_t> &data);
    void OnAcbReceived(const std::vector<uint8_t> &data);
    void OnIcbReceived(const std::vector<uint8_t> &data);
    void SetSleAddressTimeOut();

public:
    std::mutex setAddrFinishedMutex_ {};
    bool isSetAddrFinished_ = false; // guarded by setAddrFinishedMutex_
    std::condition_variable setAddrConditionVariable_ {};
    std::shared_ptr<Dli::DliProtocol> dli_ = nullptr;

private:
    void OnInitCallback(SleOpResultT result);
    bool WatchDliChannel(const VendorInterface::ReceiveCallback &receiveCallback);
    void WatcherTimeout();
    void GetFullVendorName(std::string &name);

private:
    VendorInterface::InitializeCompleteCallback initializeCompleteCallback_;
    ReceiveDataCallback eventDataCallback_ = nullptr;
    ReceiveDataCallback acbDataCallback_ = nullptr;
    ReceiveDataCallback icbDataCallback_ = nullptr;
    void* vendorHandle_ = nullptr;
    SleVendorInterfaceT *vendorInterface_ = nullptr;
    DliWatcher watcher_;
    uint32_t lpmTimer_ = 0;
    InternalCommand internalCommand_ = {0, 0};
    std::shared_ptr<SleAddress> sleAddress_ = nullptr;
    int dliInterfaceState_ = DLI_INTERFACE_CLOSED;
};

VendorInterface::VendorInterface() : impl_(std::make_unique<Impl>())
{
    HDF_LOGI("VendorInterface Constructor.");
}

VendorInterface::~VendorInterface()
{
    HDF_LOGW("VendorInterface destructor.");
    CleanUp();
}

bool VendorInterface::Initialize(InitializeCompleteCallback initializeCompleteCallback,
    const ReceiveCallback &receiveCallback)
{
    std::promise<bool> promise;
    vendorInterfaceWeak_ = shared_from_this();
    Nearlink::DoInDliThread([this, &initializeCompleteCallback, cb = receiveCallback, &promise]() {
        const ReceiveCallback &safeReceiveCallback = cb;
        bool result = impl_->Initialize(initializeCompleteCallback, safeReceiveCallback);
        promise.set_value(result);
    });
    return promise.get_future().get();
}

void VendorInterface::CleanUp()
{
    std::promise<void> promise;
    Nearlink::DoInDliThread([this, &promise]() {
        this->impl_->CleanUp();
        promise.set_value();
    });
    promise.get_future().get();
    return;
}

size_t VendorInterface::SendPacket(const std::vector<uint8_t> &packet)
{
    std::promise<size_t> promise;
    Nearlink::DoInDliThread([this, packet_ = packet, &promise]() {
        const std::vector<uint8_t> &safePacket = packet_;
        size_t result = this->impl_->SendPacket(safePacket);
        promise.set_value(result);
    });
    return promise.get_future().get();
}

void VendorInterface::OnEventReceived(const std::vector<uint8_t> &data)
{
    {
        std::lock_guard<std::mutex> lock(impl_->setAddrFinishedMutex_);
        if (impl_->isSetAddrFinished_ == false && impl_->dli_ != nullptr) {
            size_t opcodeOffset = impl_->dli_->GetPacketHeaderInfo(DLI_PACKET_TYPE_SLE_EVENT).headerSize;
            uint16_t opcode = data[opcodeOffset] | (data[opcodeOffset + 1] << OFFSET_EIGHT_BITS);
            if (opcode == DLI_SET_SLE_ADDR) {
                HDF_LOGI("SetSleAddress received the response");
                impl_->isSetAddrFinished_ = true;
                impl_->setAddrConditionVariable_.notify_all();
            }
        }
    }

    Nearlink::DoInDliThread([weakPtr = vendorInterfaceWeak_, data_ = data]() {
        auto vendorInterface = weakPtr.lock();
        if (vendorInterface == nullptr) {
            HDF_LOGE("VendorInterface::OnEventReceived: vendorInterface is nullptr");
            return;
        }
        vendorInterface->impl_->OnEventReceived(data_);
    });
    return;
}

void VendorInterface::OnAcbReceived(const std::vector<uint8_t> &data)
{
    if (!impl_) {
        return;
    }
    impl_->OnAcbReceived(data);
}

void VendorInterface::OnIcbReceived(const std::vector<uint8_t> &data)
{
    Nearlink::DoInDliThread([weakPtr = vendorInterfaceWeak_, icbData = data]() {
        auto vendorInterface = weakPtr.lock();
        if (vendorInterface == nullptr) {
            HDF_LOGE("VendorInterface::OnIcbReceived: vendorInterface is nullptr");
            return;
        }
        vendorInterface->impl_->OnIcbReceived(icbData);
    });
    return;
}

bool VendorInterface::Impl::WatchDliChannel(const VendorInterface::ReceiveCallback &receiveCallback)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    int channel[DLI_MAX_CHANNEL] = {0};
    int channelCount = vendorInterface_->op(SleOpcodeT::SLE_OP_DLI_CHANNEL_OPEN, static_cast<void *>(channel));
    if (channelCount < 1 || channelCount > DLI_MAX_CHANNEL) {
        HDF_LOGE("VendorInterface vendorInterface_->op SLE_OP_DLI_CHANNEL_OPEN failed ret:%{public}d.", channelCount);
        return false;
    }

    if (channelCount == 1) {
        auto h4 = std::make_shared<Dli::H4Protocol>(channel[0],
            std::bind(&VendorInterface::OnAcbReceived, VendorInterface::GetInstance(),
                std::placeholders::_1),
            std::bind(&VendorInterface::OnIcbReceived, VendorInterface::GetInstance(),
                std::placeholders::_1),
            std::bind(&VendorInterface::OnEventReceived, VendorInterface::GetInstance(),
                std::placeholders::_1));
        watcher_.AddFdToWatcher(channel[0], std::bind(&Dli::H4Protocol::ReadData, h4, std::placeholders::_1));
        dli_ = h4;
    } else {
        HDF_LOGE("VendorInterface invalid channel count:%{public}d.", channelCount);
        return false;
    }
    return true;
}

uint8_t *VendorInterface::Impl::TransformAddress(uint8_t *addr)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    uint8_t* data = new (std::nothrow) uint8_t[DLI_PACKET_TYPE_SIZE + DLIC_PREAMBLE_SIZE + BD_ADDR_LEN];
    if (data == nullptr) {
        HDF_LOGE("failed to create data");
        return nullptr;
    }
    uint8_t* p = data;
    *(p)++ = static_cast<uint8_t>(DLI_PACKET_TYPE_SLE_CMD);
    *(p)++ = static_cast<uint8_t>(DLI_SET_SLE_ADDR);
    *(p)++ = static_cast<uint8_t>(DLI_SET_SLE_ADDR >> OFFSET_EIGHT_BITS);
    *(p)++ = static_cast<uint8_t>(BD_ADDR_LEN);
    *(p)++ = static_cast<uint8_t>(0x00); // length domain is 2 bytes
    for (int i = 0; i < BD_ADDR_LEN; i++) {
        *(p)++ = static_cast<uint8_t>(addr[BD_ADDR_LEN - 1 - i]);
    }

    return data;
}

void VendorInterface::Impl::SetSleAddress(uint8_t *localSleAddr)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    if (dli_ == nullptr) {
        HDF_LOGE("VendorInterface SetSleAddress dli_ is nullptr");
        return;
    }
    uint8_t *hciAddrPacket = TransformAddress(localSleAddr);
    if (hciAddrPacket == nullptr) {
        HDF_LOGE("VendorInterface SetSleAddress hciAddrPacket is nullptr");
        return;
    }
    std::vector<uint8_t> hciData(&hciAddrPacket[0],
        &hciAddrPacket[DLI_PACKET_TYPE_SIZE + DLIC_PREAMBLE_SIZE + BD_ADDR_LEN]);
    internalCommand_.cb = 1;
    internalCommand_.opcode = DLI_SET_SLE_ADDR;
    dli_->SendPacket(hciData);
    delete[] reinterpret_cast<uint8_t*>(hciAddrPacket);
    HDF_LOGI("VendorInterface send mac address complete. opcode: 0x%{public}04X, cb: %{public}hu",
        internalCommand_.opcode, internalCommand_.cb);
}

void VendorInterface::Impl::GetFullVendorName(std::string &name)
{
    std::string sleChipType = OHOS::system::GetParameter(SLE_CHIP_TYPE, "");
    HDF_LOGI("slechiptype is %{public}s", sleChipType.c_str());
    if (!sleChipType.empty()) {
        name.append("_");
        name.append(sleChipType.c_str());
    }
    name.append(".z.so");
    HDF_LOGI("sle vendor library name is %{public}s", name.c_str());
}

bool VendorInterface::Impl::Initialize(VendorInterface::InitializeCompleteCallback initializeCompleteCallback,
    const VendorInterface::ReceiveCallback &receiveCallback)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    dliInterfaceState_ = DLI_INTERFACE_OPENING;
    initializeCompleteCallback_ = initializeCompleteCallback;
    eventDataCallback_ = receiveCallback.onEventReceive;
    acbDataCallback_ = receiveCallback.onAcbReceive;
    icbDataCallback_ = receiveCallback.onIcbReceive;
    std::string sleVendorFullName = SLE_VENDOR_NAME;
    GetFullVendorName(sleVendorFullName);
    vendorHandle_ = dlopen(sleVendorFullName.c_str(), RTLD_NOW);
    if (vendorHandle_ == nullptr) {
        HDF_LOGE("Vendor dlopen %{public}s failed, error code: %{public}s", sleVendorFullName.c_str(), dlerror());
        return false;
    }
    vendorInterface_ = reinterpret_cast<SleVendorInterfaceT *>(dlsym(vendorHandle_, SLE_VENDOR_INTERFACE_SYMBOL_NAME));
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface dlsym %{public}s failed.", SLE_VENDOR_INTERFACE_SYMBOL_NAME);
        return false;
    }
    sleAddress_ = SleAddress::GetDeviceAddress();
    std::vector<uint8_t> address = { 0, 0, 0, 0, 0, 0 };
    if (sleAddress_ != nullptr) {
        sleAddress_->ReadAddress(address);
    }
    vendorInterface_->init();
    if (!WatchDliChannel(receiveCallback)) {
        HDF_LOGE("VendorInterface WatchDliChannel failed.");
        return false;
    }
    if (!watcher_.Start()) {
        HDF_LOGE("VendorInterface watcher start failed.");
        return false;
    }

    if (sleAddress_ != nullptr) {
        std::string strAddress;
        sleAddress_->ParseAddressToString(address, strAddress);
        HDF_LOGI("VendorInterface local addr: %{public}s", sleAddress_->GetEncryptAddr(strAddress).c_str());
    }
    SetSleAddress(address.data());
    std::unique_lock<std::mutex> lock(setAddrFinishedMutex_);
    if (!setAddrConditionVariable_.wait_for(lock, std::chrono::milliseconds(SET_ADDR_TIME_OUT_MS),
        [this]() -> bool { return isSetAddrFinished_; })) {
        Nearlink::DoInDliThread([this]() -> void {
            SetSleAddressTimeOut();
        });
    }
    return true;
}

void VendorInterface::Impl::CleanUp()
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface::CleanUp, vendorInterface_ is nullptr.");
        return;
    }
    watcher_.Stop();
    vendorInterface_->op(SleOpcodeT::SLE_OP_DLI_CHANNEL_CLOSE, nullptr);
    vendorInterface_->close();
    dli_ = nullptr;
    vendorInterface_ = nullptr;
    initializeCompleteCallback_ = nullptr;
    eventDataCallback_ = nullptr;
    acbDataCallback_ = nullptr;
    icbDataCallback_ = nullptr;
    if ((vendorHandle_ == nullptr) || dlclose(vendorHandle_)) {
        HDF_LOGE("VendorInterface vendorHandle_ is wrong.");
    }
    vendorHandle_ = nullptr;
    dliInterfaceState_ = DLI_INTERFACE_CLOSED;
    {
        std::unique_lock<std::mutex> lock(setAddrFinishedMutex_);
        isSetAddrFinished_ = false;
    }
}

size_t VendorInterface::Impl::SendPacket(const std::vector<uint8_t> &packet)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    if (vendorInterface_ == nullptr || dli_ == nullptr) {
        HDF_LOGE("VendorInterface::SendPacket, vendorInterface_ is nullptr.");
        return SLE_VENDOR_INVALID_DATA_LEN;
    }

    watcher_.SetTimeout(std::chrono::milliseconds(lpmTimer_), std::bind(&Impl::WatcherTimeout, this));

    return dli_->SendPacket(packet);
}

// No lock is required through OnEventReceived invoking.
void VendorInterface::Impl::OnInitCallback(SleOpResultT result)
{
    HDF_LOGI("VendorInterface %{public}s, ", __func__);
    if (initializeCompleteCallback_) {
        initializeCompleteCallback_(result == SLE_OP_RESULT_SUCCESS);
        initializeCompleteCallback_ = nullptr;
    }

    uint32_t lpmTimer = 0;
    lpmTimer_ = lpmTimer;
    watcher_.SetTimeout(std::chrono::milliseconds(lpmTimer), std::bind(&Impl::WatcherTimeout, this));
}

void VendorInterface::Impl::OnEventReceived(const std::vector<uint8_t> &data)
{
    HDF_LOGI("VendorInterface %{public}s", __func__);
    if (dliInterfaceState_ == DLI_INTERFACE_OPENED) {
        eventDataCallback_(data);
        return;
    }
    if (dli_ == nullptr) {
        HDF_LOGE("VendorInterface OnEventReceived dli_ is nullptr");
        return;
    }

    size_t opcodeOffset = dli_->GetPacketHeaderInfo(DLI_PACKET_TYPE_SLE_EVENT).headerSize;
    if (data.size() <= opcodeOffset + OFFSET_STATUS) {
        HDF_LOGE("Invalid data length: %{public}zu", data.size());
        return;
    }
    uint16_t eventOpcode = data[0] | (data[1] << OFFSET_EIGHT_BITS);
    uint16_t opcode = data[opcodeOffset] | (data[opcodeOffset + 1] << OFFSET_EIGHT_BITS);
    if (internalCommand_.cb != 0 && (internalCommand_.opcode == opcode)) {
        internalCommand_.cb = 0;
        if (data[opcodeOffset + OFFSET_STATUS] == 0) {
            dliInterfaceState_ = DLI_INTERFACE_OPENED;
            OnInitCallback(SLE_OP_RESULT_SUCCESS);
        } else {
            HDF_LOGE("VendorInterface Invalid status: %{public}d", data[opcodeOffset + OFFSET_STATUS]);
            OnInitCallback(SLE_OP_RESULT_FAIL);
            CleanUp();
        }
    } else {
        HDF_LOGI("recv unexpected eventOpcode:0x%{public}x opcode:0x%{public}x", eventOpcode, opcode);
    }
}

void VendorInterface::Impl::OnAcbReceived(const std::vector<uint8_t> &data)
{
    if (acbDataCallback_ == nullptr) {
        HDF_LOGE("acbDataCallback_ is nullptr");
        return;
    }
    HDF_LOGD("VendorInterface %{public}s", __func__);
    acbDataCallback_(data);
}

void VendorInterface::Impl::OnIcbReceived(const std::vector<uint8_t> &data)
{
    if (icbDataCallback_ == nullptr) {
        HDF_LOGE("icbDataCallback_ is nullptr");
        return;
    }
    HDF_LOGD("VendorInterface %{public}s", __func__);
    icbDataCallback_(data);
}

void VendorInterface::Impl::WatcherTimeout()
{
    HDF_LOGI("fd wait out of time, no data ready");
}

void VendorInterface::Impl::SetSleAddressTimeOut()
{
    HDF_LOGI("SetSleAddressTimeOut, retry SetSleAddress");
    std::vector<uint8_t> address = { 0, 0, 0, 0, 0, 0 };
    if (sleAddress_ != nullptr) {
        sleAddress_->ReadAddress(address);
    }
    SetSleAddress(address.data());
}

}  // namespace V1_1
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS