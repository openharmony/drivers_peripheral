/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "vendor_interface.h"

#include <thread>

#include <dlfcn.h>

#include <hdf_log.h>
#include <securec.h>

#include "bluetooth_address.h"
#include "bt_hal_constant.h"
#include "h4_protocol.h"
#include "mct_protocol.h"

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
namespace V1_0 {
constexpr size_t BT_VENDOR_INVALID_DATA_LEN = 0;
BtVendorCallbacksT VendorInterface::vendorCallbacks_ = {
    .size = sizeof(BtVendorCallbacksT),
    .initCb = VendorInterface::OnInitCallback,
    .alloc = VendorInterface::OnMallocCallback,
    .dealloc = VendorInterface::OnFreeCallback,
    .xmitCb = VendorInterface::OnCmdXmitCallback,
};

VendorInterface::VendorInterface()
{}

VendorInterface::~VendorInterface()
{
    CleanUp();
}

bool VendorInterface::WatchHciChannel(const ReceiveCallback &receiveCallback)
{
    int channel[HCI_MAX_CHANNEL] = {0};
    int channelCount = vendorInterface_->op(BtOpcodeT::BT_OP_HCI_CHANNEL_OPEN, channel);
    if (channelCount < 1 || channelCount > HCI_MAX_CHANNEL) {
        HDF_LOGE("vendorInterface_->op BT_OP_HCI_CHANNEL_OPEN failed ret:%d.", channelCount);
        return false;
    }

    if (channelCount == 1) {
        auto h4 = std::make_shared<Hci::H4Protocol>(channel[0],
            receiveCallback.onAclReceive,
            receiveCallback.onScoReceive,
            std::bind(&VendorInterface::OnEventReceived, this, std::placeholders::_1));
        watcher_.AddFdToWatcher(channel[0], std::bind(&Hci::H4Protocol::ReadData, h4, std::placeholders::_1));
        hci_ = h4;
    } else {
        auto mct = std::make_shared<Hci::MctProtocol>(channel,
            receiveCallback.onAclReceive,
            receiveCallback.onScoReceive,
            std::bind(&VendorInterface::OnEventReceived, this, std::placeholders::_1));
        watcher_.AddFdToWatcher(
            channel[hci_channels_t::HCI_ACL_IN], std::bind(&Hci::MctProtocol::ReadAclData, mct, std::placeholders::_1));
        watcher_.AddFdToWatcher(
            channel[hci_channels_t::HCI_EVT], std::bind(&Hci::MctProtocol::ReadEventData, mct, std::placeholders::_1));
        hci_ = mct;
    }

    return true;
}

bool VendorInterface::Initialize(
    InitializeCompleteCallback initializeCompleteCallback, const ReceiveCallback &receiveCallback)
{
    HDF_LOGI("VendorInterface %{public}s, ", __func__);
    initializeCompleteCallback_ = initializeCompleteCallback;
    eventDataCallback_ = receiveCallback.onEventReceive;

    vendorHandle_ = dlopen(BT_VENDOR_NAME, RTLD_NOW);
    if (vendorHandle_ == nullptr) {
        HDF_LOGE("VendorInterface dlopen %{public}s failed, error code: %{public}s", BT_VENDOR_NAME, dlerror());
        return false;
    }

    vendorInterface_ =
        reinterpret_cast<BtVendorInterfaceT *>(dlsym(vendorHandle_, BT_VENDOR_INTERFACE_SYMBOL_NAME));
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface dlsym %{public}s failed.", BT_VENDOR_INTERFACE_SYMBOL_NAME);
        return false;
    }

    auto bluetoothAddress = BluetoothAddress::GetDeviceAddress();
    std::vector<uint8_t> address = { 0, 0, 0, 0, 0, 0 };
    if (bluetoothAddress != nullptr) {
        bluetoothAddress->ReadAddress(address);
    }

    int result = vendorInterface_->init(&vendorCallbacks_, address.data());
    if (result != 0) {
        HDF_LOGE("vendorInterface_->init failed.");
        return false;
    }

    result = vendorInterface_->op(BtOpcodeT::BT_OP_POWER_ON, nullptr);
    if (result != 0) {
        HDF_LOGE("vendorInterface_->op BT_OP_POWER_ON failed.");
        return false;
    }

    if (!WatchHciChannel(receiveCallback)) {
        return false;
    }

    if (!watcher_.Start()) {
        HDF_LOGE("watcher start failed.");
        return false;
    }

    vendorInterface_->op(BtOpcodeT::BT_OP_INIT, nullptr);

    return true;
}

void VendorInterface::CleanUp()
{
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface::CleanUp, vendorInterface_ is nullptr.");
        return;
    }

    watcher_.Stop();

    vendorInterface_->op(BtOpcodeT::BT_OP_LPM_DISABLE, nullptr);
    vendorInterface_->op(BtOpcodeT::BT_OP_HCI_CHANNEL_CLOSE, nullptr);
    vendorInterface_->op(BtOpcodeT::BT_OP_POWER_OFF, nullptr);
    vendorInterface_->close();

    hci_ = nullptr;
    vendorInterface_ = nullptr;
    initializeCompleteCallback_ = nullptr;
    eventDataCallback_ = nullptr;
    dlclose(vendorHandle_);
}

size_t VendorInterface::SendPacket(Hci::HciPacketType type, const std::vector<uint8_t> &packet)
{
    std::lock_guard<std::mutex> lock(wakeupMutex_);
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface::SendPacket, vendorInterface_ is nullptr.");
        return BT_VENDOR_INVALID_DATA_LEN;
    }

    {
        activity_ = true;
        watcher_.SetTimeout(std::chrono::milliseconds(lpmTimer_), std::bind(&VendorInterface::WatcherTimeout, this));
        if (!wakeupLock_) {
            vendorInterface_->op(BtOpcodeT::BT_OP_WAKEUP_LOCK, nullptr);
            wakeupLock_ = true;
        }
    }

    return hci_->SendPacket(type, packet);
}

void VendorInterface::OnInitCallback(BtOpResultT result)
{
    HDF_LOGI("%{public}s, ", __func__);
    if (VendorInterface::GetInstance()->initializeCompleteCallback_) {
        VendorInterface::GetInstance()->initializeCompleteCallback_(result == BTC_OP_RESULT_SUCCESS);
        VendorInterface::GetInstance()->initializeCompleteCallback_ = nullptr;
    }

    uint32_t lpmTimer = 0;
    if (VendorInterface::GetInstance()->vendorInterface_->op(BtOpcodeT::BT_OP_GET_LPM_TIMER, &lpmTimer) != 0) {
        HDF_LOGE("Vector interface BT_OP_GET_LPM_TIMER failed");
    }
    VendorInterface::GetInstance()->lpmTimer_ = lpmTimer;

    VendorInterface::GetInstance()->vendorInterface_->op(BtOpcodeT::BT_OP_LPM_ENABLE, nullptr);

    VendorInterface::GetInstance()->watcher_.SetTimeout(std::chrono::milliseconds(lpmTimer),
        std::bind(&VendorInterface::WatcherTimeout, VendorInterface::GetInstance()));
}

void *VendorInterface::OnMallocCallback(int size)
{
    static int MAX_BUFFER_SIZE = 1024;
    if (size <= 0 || size > MAX_BUFFER_SIZE) {
        HDF_LOGE("%{public}s, size is invalid", __func__);
        return nullptr;
    }
    return malloc(size);
}

void VendorInterface::OnFreeCallback(void *buf)
{
    if (buf != nullptr) {
        free(buf);
    }
}

size_t VendorInterface::OnCmdXmitCallback(uint16_t opcode, void *buf)
{
    HC_BT_HDR *hdr = reinterpret_cast<HC_BT_HDR *>(buf);

    VendorInterface::GetInstance()->vendorSentOpcode_ = opcode;

    return VendorInterface::GetInstance()->SendPacket(
        Hci::HCI_PACKET_TYPE_COMMAND, std::vector<uint8_t>(hdr->data, hdr->data + hdr->len));
}

void VendorInterface::OnEventReceived(const std::vector<uint8_t> &data)
{
    if (data[0] == Hci::HCI_EVENT_CODE_VENDOR_SPECIFIC) {
        size_t buffSize = sizeof(HC_BT_HDR) + data.size();
        HC_BT_HDR *buff = reinterpret_cast<HC_BT_HDR *>(new uint8_t[buffSize]);
        buff->event = data[0];
        buff->len = data.size();
        buff->offset = 0;
        buff->layer_specific = 0;
        (void)memcpy_s(buff->data, buffSize - sizeof(HC_BT_HDR), data.data(), data.size());
        if (vendorInterface_ && vendorInterface_->op) {
            vendorInterface_->op(BtOpcodeT::BT_OP_EVENT_CALLBACK, buff);
        }
        delete[] buff;
    } else if (vendorSentOpcode_ != 0 && data[0] == Hci::HCI_EVENT_CODE_COMMAND_COMPLETE) {
        uint8_t opcodeOffset = hci_->GetPacketHeaderInfo(Hci::HCI_PACKET_TYPE_EVENT).headerSize + 1;
        uint16_t opcode = data[opcodeOffset] + (data[opcodeOffset + 1] << 0x08);
        if (opcode == vendorSentOpcode_) {
            size_t buffSize = sizeof(HC_BT_HDR) + data.size();
            HC_BT_HDR *buff = reinterpret_cast<HC_BT_HDR *>(new uint8_t[buffSize]);
            buff->event = data[0];
            buff->len = data.size();
            buff->offset = 0;
            buff->layer_specific = 0;
            (void)memcpy_s(buff->data, buffSize - sizeof(HC_BT_HDR), data.data(), data.size());
            vendorSentOpcode_ = 0;
            if (vendorInterface_ && vendorInterface_->op) {
                vendorInterface_->op(BtOpcodeT::BT_OP_EVENT_CALLBACK, buff);
            }
            delete[] buff;
        }
    }

    eventDataCallback_(data);
}

void VendorInterface::WatcherTimeout()
{
    std::lock_guard<std::mutex> lock(wakeupMutex_);
    if (!activity_ && wakeupLock_ && vendorInterface_ && vendorInterface_->op) {
        vendorInterface_->op(BtOpcodeT::BT_OP_WAKEUP_UNLOCK, nullptr);
        wakeupLock_ = false;
    }
    activity_ = false;
}
}  // namespace V1_0
}  // namespace Hci
}  // namespace Bluetooth
}  // namespace HDI
}  // namespace OHOS
