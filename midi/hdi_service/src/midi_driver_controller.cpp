/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "midi_driver_controller.h"

#include <ctime>
#include <iomanip>
#include <fstream>
#include <hdf_base.h>
#include <iostream>
#include <sstream>
#include <unordered_set>
#include <sys/eventfd.h>

#include "securec.h"
#include "midi_log.h"

#define HDF_LOG_TAG midi_driver_controller

namespace OHOS {
namespace HDI {
namespace Midi {
namespace V1_0 {
namespace {
    constexpr int32_t MAX_WORK_BUFFER_WORDS = 256;
    constexpr size_t WORK_BUFFER_SIZE = sizeof(uint32_t) * MAX_WORK_BUFFER_WORDS;
    constexpr uint8_t UMP_MT_SYSTEM = 0x1;
    constexpr uint32_t UMP_SHIFT_MT = 28;
    constexpr uint32_t UMP_SHIFT_STATUS = 16;
    constexpr uint32_t UMP_MASK_NIBBLE = 0xF;
    constexpr uint32_t UMP_MASK_BYTE = 0xFF;
    constexpr uint8_t MIDI_TIMING_CLOCK = 0xF8;
    constexpr int64_t NSEC_PER_SEC = 1000000000;
    constexpr int32_t MIDI_BYTE_HEX_WIDTH = 2;
    constexpr int32_t MIDI_PORT_DIRECTION_COUNT = 2;
    constexpr int32_t UMP_WORD_HEX_WIDTH = 8;

    bool IsMidiClockMessage(uint8_t byte)
    {
        return byte == MIDI_TIMING_CLOCK;
    }

    bool IsUmpClockMessage(const UmpPacket &packet)
    {
        uint8_t mt = (packet.Word(0) >> UMP_SHIFT_MT) & UMP_MASK_NIBBLE;
        if (mt == UMP_MT_SYSTEM) {
            uint8_t status = (packet.Word(0) >> UMP_SHIFT_STATUS) & UMP_MASK_BYTE;
            return IsMidiClockMessage(status);
        }
        return false;
    }
}

static void ReadVendorIdAndProductId(int32_t card, std::string &idVendor, std::string &idProduct)
{
    std::string path = "/proc/asound/card" + std::to_string(card) + "/usbid";
    std::ifstream file(path);
    idVendor = "";
    idProduct = "";
    if (!file.is_open()) {
        return;
    }
    std::string line;
    if (!std::getline(file, line)) {
        return;
    }
    size_t colonPos =  line.find(':');
    if (colonPos == std::string::npos) {
        return;
    }

    idVendor = line.substr(0, colonPos);
    idProduct = line.substr(colonPos + 1);
}

static void ReadDeviceName(int32_t card, std::string &deviceName)
{
    std::string path = "/proc/asound/card" + std::to_string(card) + "/id";
    std::ifstream file(path);
    deviceName = "";
    if (!file.is_open()) {
        return;
    }
    std::string line;
    if (!std::getline(file, line)) {
        return;
    }
    deviceName = line;
}

static void ReadUsbBus(int32_t card, std::string &bus)
{
    std::string path = "/proc/asound/card" + std::to_string(card) + "/usbbus";
    std::ifstream file(path);
    if (!file.is_open()) {
        return;
    }
    if (!std::getline(file, bus)) {
        return;
    }
}

static int64_t MakeDeviceId(int32_t card)
{
    std::string idVendor;
    std::string idProduct;
    std::string usbbus;

    ReadVendorIdAndProductId(card, idVendor, idProduct);
    ReadUsbBus(card, usbbus);
    std::hash<std::string> hasher;
    return static_cast<int64_t>(hasher(idVendor + idProduct + usbbus));
}

static std::string MakeDeviceFileName(int32_t card, int32_t device)
{
    return "midiC" + std::to_string(card) + "D" + std::to_string(device);
}

static std::string MakeHwName(int32_t card, int32_t device, uint32_t subdevice)
{
    return "hw:" + std::to_string(card) + "," + std::to_string(device) + "," + std::to_string(subdevice);
}

static std::vector<MidiPortInfo> MakeMidiPortInfos(const DeviceInfo device)
{
    std::vector<MidiPortInfo> portInfos;
    uint32_t portId = 0;
    for (const auto &port : device.outputPorts) {
        MidiPortInfo portInfo;
        portInfo.portId = portId++;
        portInfo.name = port.name;
        portInfo.direction = PORT_DIRECTION_OUTPUT;
        portInfos.push_back(portInfo);
    }

    for (const auto &port : device.inputPorts) {
        MidiPortInfo portInfo;
        portInfo.portId = portId++;
        portInfo.name = port.name;
        portInfo.direction = PORT_DIRECTION_INPUT;
        portInfos.push_back(portInfo);
    }
    return portInfos;
}

static std::vector<MidiDeviceInfo> MakeMidiDeviceInfos(const std::vector<DeviceInfo> &deviceInfos)
{
    std::vector<MidiDeviceInfo> devices;
    for (const auto &device : deviceInfos) {
        MidiDeviceInfo dev;
        dev.deviceId = device.deviceId;
        dev.productId = device.idProduct;
        dev.vendorId = device.idVendor;
        dev.deviceName = device.deviceName;
        dev.protocol = device.is_ump ? MIDI_PROTOCOL_2_0 : MIDI_PROTOCOL_1_0;
        dev.ports = MakeMidiPortInfos(device);
        devices.push_back(dev);
    }
    return devices;
}

static int64_t GetCurNano()
{
    int64_t result = -1; // -1 for bad result.
    struct timespec time;
    clockid_t clockId = CLOCK_MONOTONIC;
    int ret = clock_gettime(clockId, &time);
    if (ret < 0) {
        HDF_LOGI("%{public}s GetCurNanoTime fail, result:%{public}d", __func__, ret);
        return result;
    }
    result = (time.tv_sec * NSEC_PER_SEC) + time.tv_nsec;
    return result;
}

Midi1Device::~Midi1Device()
{
    HDF_LOGI("%{public}s enter, deviceId: %{public}" PRId64, __func__, info_.deviceId);
    // Phase 1: Set quit flags and collect contexts while holding the lock
    std::vector<std::shared_ptr<InputContext>> inputsToClose;
    std::vector<std::shared_ptr<OutputContext>> outputsToClose;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        HDF_LOGI("%{public}s Phase1: holding lock, setting quit flags", __func__);
        for (auto& pair : inputs_) {
            auto ctx = pair.second;
            ctx->quit = true;
            // Wake up thread
            if (ctx->eventFd != -1) {
                uint64_t u = 1;
                write(ctx->eventFd, &u, sizeof(uint64_t));
                HDF_LOGI("%{public}s wake up input thread, portId: %{public}u", __func__, pair.first);
            }
            inputsToClose.push_back(ctx);
        }
        for (auto& pair : outputs_) {
            outputsToClose.push_back(pair.second);
        }
        inputs_.clear();
        outputs_.clear();
        HDF_LOGI("%{public}s Phase1: releasing lock", __func__);
    } // Lock released here

    // Phase 2: Wait for threads and cleanup resources without holding the lock
    HDF_LOGI("%{public}s Phase2: waiting for threads and cleanup (no lock)", __func__);
    for (auto& ctx : inputsToClose) {
        if (ctx->thread.joinable()) {
            ctx->thread.join();
        }
        if (ctx->rawmidi) {
            snd_rawmidi_close(ctx->rawmidi);
            HDF_LOGI("%{public}s Phase2: rawmidi closed", __func__);
        }
        if (ctx->eventFd != -1) {
            close(ctx->eventFd);
            HDF_LOGI("%{public}s Phase2: eventFd closed", __func__);
        }
    }
    for (auto& ctx : outputsToClose) {
        if (ctx->rawmidi) {
            snd_rawmidi_close(ctx->rawmidi);
        }
    }
    HDF_LOGI("%{public}s exit, deviceId: %{public}" PRId64, __func__, info_.deviceId);
}

int32_t Midi1Device::OpenInputPort(uint32_t portId, const sptr<IMidiCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (portId < info_.outputPorts.size()) {
        HDF_LOGE("%{public}s portId %{public}u < outputPorts.size %{public}zu, invalid input port",
                 __func__, portId, info_.outputPorts.size());
        return HDF_FAILURE;
    }
    portId -= info_.outputPorts.size();
    if (portId >= info_.inputPorts.size()) {
        HDF_LOGE("%{public}s portId %{public}u >= inputPorts.size %{public}zu, out of range",
                 __func__, portId, info_.inputPorts.size());
        return HDF_FAILURE;
    }
    if (inputs_.find(portId) != inputs_.end()) {
        HDF_LOGE("%{public}s input port %{public}u already opened", __func__, portId);
        return HDF_FAILURE;
    }

    const auto& port = info_.inputPorts[portId];
    snd_rawmidi_t *rawmidi;
    auto hwname = MakeHwName(port.card, port.device, port.subdevice);
    auto result = ::snd_rawmidi_open(&rawmidi, nullptr, hwname.c_str(), SND_RAWMIDI_NONBLOCK);
    if (result < 0) {
        HDF_LOGI("%{public}s snd_rawmidi_open error : %{public}d, name :%{public}s", __func__, result, hwname.c_str());
        return HDF_FAILURE;
    }

    auto count = ::snd_rawmidi_poll_descriptors_count(rawmidi);
    if (count <= 0) {
        ::snd_rawmidi_close(rawmidi);
        HDF_LOGI("%{public}s snd_rawmidi_poll_descriptors_count error : %{public}d", __func__, count);
        return HDF_FAILURE;
    }

    std::vector<struct pollfd> pfds {static_cast<std::size_t>(count)};
    ::snd_rawmidi_poll_descriptors(rawmidi, &pfds[0], count);
    auto ctx = std::make_shared<InputContext>();
    ctx->quit = false;
    ctx->rawmidi = rawmidi;
    ctx->pfds = pfds;
    ctx->dataCallback = callback;
    ctx->processor = std::make_shared<UmpProcessor>();
    // Create EventFD for wake-up
    ctx->eventFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->eventFd == -1) {
        ::snd_rawmidi_close(rawmidi);
        return HDF_FAILURE;
    }

    ctx->thread = std::thread([this, ctx]() { this->InputThreadLoop(ctx); });
    inputs_[portId] = ctx;
    HDF_LOGI("%{public}s success, portId:%{public}u", __func__, portId);
    return HDF_SUCCESS;
}

int32_t Midi1Device::CloseInputPort(uint32_t portId)
{
    HDF_LOGI("%{public}s enter, portId: %{public}u, deviceId: %{public}" PRId64,
             __func__, portId, info_.deviceId);
    std::shared_ptr<InputContext> ctx;

    // Phase 1: Set quit flag and remove from map while holding the lock
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (portId < info_.outputPorts.size()) {
            HDF_LOGE("%{public}s portId %{public}u < outputPorts.size %{public}zu, invalid input port",
                     __func__, portId, info_.outputPorts.size());
            return HDF_FAILURE;
        }
        portId -= info_.outputPorts.size();
        auto it = inputs_.find(portId);
        if (it == inputs_.end()) {
            HDF_LOGE("%{public}s input port %{public}u not found in inputs_", __func__, portId);
            return HDF_FAILURE;
        }

        ctx = it->second;
        ctx->quit = true;

        // Signal Epoll to wake up
        if (ctx->eventFd != -1) {
            uint64_t u = 1;
            write(ctx->eventFd, &u, sizeof(uint64_t));
        }
        inputs_.erase(it);
    } // Lock released here
    if (ctx->thread.joinable()) {
        ctx->thread.join();
    }
    if (ctx->rawmidi) {
        snd_rawmidi_close(ctx->rawmidi);
    }
    if (ctx->eventFd != -1) {
        close(ctx->eventFd);
    }
    ctx->processor = nullptr;
    HDF_LOGI("%{public}s exit, portId: %{public}u", __func__, portId);

    return HDF_SUCCESS;
}

int32_t Midi1Device::OpenOutputPort(uint32_t portId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (portId >= info_.outputPorts.size()) {
        HDF_LOGE("%{public}s portId %{public}u >= outputPorts.size %{public}zu, out of range",
                 __func__, portId, info_.outputPorts.size());
        return HDF_FAILURE;
    }
    if (outputs_.find(portId) != outputs_.end()) {
        HDF_LOGE("%{public}s output port %{public}u already opened", __func__, portId);
        return HDF_FAILURE;
    }

    const auto& portInfo = info_.outputPorts[portId];
    auto ctx = std::make_shared<OutputContext>();
    ctx->processor = std::make_shared<UmpProcessor>();

    std::string hwname = MakeHwName(portInfo.card, portInfo.device, portInfo.subdevice);
    if (snd_rawmidi_open(nullptr, &ctx->rawmidi, hwname.c_str(), 0) < 0) {
        HDF_LOGE("Midi1Device: Failed to open output rawmidi");
        return HDF_FAILURE;
    }
    outputs_[portId] = ctx;
    return HDF_SUCCESS;
}

int32_t Midi1Device::CloseOutputPort(uint32_t portId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = outputs_.find(portId);
    if (it == outputs_.end()) {
        HDF_LOGI("%{public}s output port %{public}u not found, already closed", __func__, portId);
        return HDF_SUCCESS;
    }

    if (it->second->rawmidi) snd_rawmidi_close(it->second->rawmidi);
    it->second->processor = nullptr;
    outputs_.erase(it);
    return HDF_SUCCESS;
}

int32_t Midi1Device::SendMidiMessages(uint32_t portId, const std::vector<MidiMessage> &messages)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = outputs_.find(portId);
    if (it == outputs_.end()) {
        HDF_LOGE("%{public}s output port %{public}u not found, not opened", __func__, portId);
        return HDF_FAILURE;
    }

    if (it->second->processor == nullptr) {
        HDF_LOGE("%{public}s processor is nullptr", __func__);
        return HDF_FAILURE;
    }

    for (const auto& msg : messages) {
        std::vector<uint8_t> midi1Buffer;
        it->second->processor->ProcessUmp(msg.data.data(), msg.data.size(),
            [&midi1Buffer](const uint8_t* data, size_t len) {
                for (size_t i = 0; i < len; ++i) {
                    midi1Buffer.push_back(data[i]);
                }
            });
        if (!midi1Buffer.empty()) {
            int64_t written = ::snd_rawmidi_write(it->second->rawmidi, midi1Buffer.data(), midi1Buffer.size());
            if (written < 0) {
                HDF_LOGE("%{public}s snd_rawmidi_write failed: %{public}" PRId64, __func__, written);
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

void Midi1Device::ProcessInputEvent(std::shared_ptr<InputContext> ctx, uint8_t* buffer, size_t bufferSize)
{
    HDF_LOGD("%{public}s enter, bufferSize: %{public}zu", __func__, bufferSize);
    // Filter timing clock messages (0xF8) for midiStream log
    std::ostringstream midiStream;
    for (size_t i = 0; i < static_cast<size_t>(bufferSize); i++) {
        if (!IsMidiClockMessage(buffer[i])) {
            midiStream << std::hex << std::setw(MIDI_BYTE_HEX_WIDTH) << std::setfill('0') <<
                static_cast<uint32_t>(buffer[i]) << " ";
        }
    }
    if (!midiStream.str().empty()) {
        HDF_LOGI("%{public}s midiStream 1.0: %{public}s", __func__, midiStream.str().c_str());
    }
    auto processor = ctx->processor;
    if (processor == nullptr) {
        HDF_LOGE("%{public}s processor is nullptr, setting quit flag", __func__);
        ctx->quit = true;
        return;
    }
    std::vector<UmpPacket> results;
    processor->ProcessBytes(buffer, static_cast<size_t>(bufferSize), [&](const UmpPacket &p) {
        results.push_back(p);
    });
    HDF_LOGD("%{public}s processed %{public}zu UMP packets", __func__, results.size());
    for (auto p : results) {
        // Filter clock messages for umpStream log
        if (!IsUmpClockMessage(p)) {
            std::ostringstream umpStream;
            for (uint8_t i = 0; i < p.WordCount(); i++) {
                umpStream << std::hex << std::setw(UMP_WORD_HEX_WIDTH) << std::setfill('0') << p.Word(i) << " ";
            }
            HDF_LOGD("%{public}s umpStream 1.0: %{public}s", __func__, umpStream.str().c_str());
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (ctx->dataCallback && !results.empty()) {
        std::vector<MidiMessage> eventList;
        MidiMessage message;
        message.timestamp = GetCurNano();
        for (auto p : results) {
            for (uint8_t i = 0; i < p.WordCount(); i++) {
                message.data.push_back(p.Word(i));
            }
        }
        eventList.push_back(message);
        HDF_LOGD("%{public}s calling OnMidiDataReceived with %{public}zu messages", __func__, eventList.size());
        ctx->dataCallback->OnMidiDataReceived(eventList);
    }
    HDF_LOGD("%{public}s exit", __func__);
}

void Midi1Device::InputThreadLoop(std::shared_ptr<InputContext> ctx)
{
    HDF_LOGI("%{public}s enter, deviceId: %{public}" PRId64, __func__, info_.deviceId);

    // Send empty callback at thread startup to trigger framework-level thread priority elevation
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ctx->dataCallback) {
            std::vector<MidiMessage> emptyEventList;
            ctx->dataCallback->OnMidiDataReceived(emptyEventList);
        }
    }

    EpollHandler epoll;
    if (!epoll.init()) {
        HDF_LOGE("%{public}s epoll create failed", __func__);
        return;
    }
    struct epoll_event event[ctx->pfds.size() + 1]; // +1 for eventFd
    // Add ALSA fds
    HDF_LOGI("%{public}s adding %{public}zu ALSA fds to epoll", __func__, ctx->pfds.size());
    for (size_t i = 0; i < ctx->pfds.size(); i++) {
        epoll.add(ctx->pfds[i].fd, event[i], EPOLLIN);
    }

    // Add Wakeup fd
    struct epoll_event evWakeup;
    epoll.add(ctx->eventFd, evWakeup, EPOLLIN, &ctx->eventFd); // Use ptr to identify
    HDF_LOGI("%{public}s epoll setup complete, entering main loop", __func__);

    auto src = std::make_unique<uint8_t[]>(WORK_BUFFER_SIZE);
    while (!ctx->quit) {
        epoll.poll([&](void *ptr, int32_t) {
            if (ctx->quit) {
                HDF_LOGI("%{public}s quit flag set, exiting poll callback", __func__);
                return;
            }
            // Check if it's the wakeup event
            if (ptr == &ctx->eventFd) {
                HDF_LOGI("%{public}s received wakeup event", __func__);
                uint64_t u;
                read(ctx->eventFd, &u, sizeof(uint64_t));
                return; // Just wake up loop to check ctx->quit
            }
            // ALSA Event
            int64_t len = ::snd_rawmidi_read(ctx->rawmidi, src.get(), WORK_BUFFER_SIZE);
            if (len < 0) {
                HDF_LOGI("%{public}s snd_rawmidi_read error : %{public}" PRId64, __func__, len);
                ctx->quit = true;
                return;
            }
            if (len > 0) {
                ProcessInputEvent(ctx, src.get(), static_cast<size_t>(len));
            }
        });
    }
    for (size_t i = 0; i < ctx->pfds.size(); i++) {
        epoll.del(ctx->pfds[i].fd, event[i]);
    }
    epoll.finalize();
    HDF_LOGI("%{public}s exit, deviceId: %{public}" PRId64, __func__, info_.deviceId);
}

MidiDriverController *MidiDriverController::GetInstance()
{
    static MidiDriverController instance;
    return &instance;
}

void MidiDriverController::CleanupRemovedDevices(const std::vector<DeviceInfo> &oldDeviceList)
{
    std::unordered_set<int64_t> currentDeviceIds;
    for (const auto &device : deviceList_) {
        currentDeviceIds.insert(device.deviceId);
    }
    for (const auto &oldDevice : oldDeviceList) {
        if (currentDeviceIds.find(oldDevice.deviceId) == currentDeviceIds.end()) {
            HDF_LOGI("%{public}s: Device detected removal: %{public}" PRId64 "(Card: %{public}d, Device: %{public}d)",
                __func__, oldDevice.deviceId, oldDevice.card, oldDevice.device);
            CleanupDeviceInputPorts(oldDevice.deviceId);
        }
    }
}

void MidiDriverController::CleanupDeviceInputPorts(int64_t deviceId)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it != activeDrivers_.end()) {
        HDF_LOGI("%{public}s: Removing driver resources for device %{public}" PRId64, __func__, deviceId);
        activeDrivers_.erase(it);
    } else {
        HDF_LOGD("%{public}s: Device %{public}" PRId64 " was not active, no cleanup needed.", __func__, deviceId);
    }
}
void MidiDriverController::PopulateMidi1Ports(snd_ctl_t *ctl, int32_t device, DeviceInfo &devInfo)
{
    for (auto direction = 0; direction < MIDI_PORT_DIRECTION_COUNT; ++direction) { // 0 : output, 1 : input
        snd_rawmidi_info_t *info;
        snd_rawmidi_info_alloca(&info);
        ::snd_rawmidi_info_set_device(info, device);
        ::snd_rawmidi_info_set_stream(info, static_cast<snd_rawmidi_stream_t>(direction));
        ::snd_rawmidi_info_set_subdevice(info, 0);
        if (::snd_ctl_rawmidi_info(ctl, info) < 0) {
            continue;
        }
        std::string devname = ::snd_rawmidi_info_get_name(info);
        uint32_t subdevices_count = ::snd_rawmidi_info_get_subdevices_count(info);

        for (uint32_t sub = 0; sub < subdevices_count; ++sub) {
            ::snd_rawmidi_info_set_subdevice(info, sub);
            if (::snd_ctl_rawmidi_info(ctl, info) < 0) {
                continue;
            }
            PortInfo portInfo;
            const char *name = ::snd_rawmidi_info_get_subdevice_name(info);
            portInfo.name = name != nullptr ? name : devname + " " + std::to_string(sub);
            portInfo.card = devInfo.card;
            portInfo.device = device;
            portInfo.subdevice = sub;
            portInfo.groups = 0;
            portInfo.umpStartGroup = 0;
            portInfo.numUmpGroupsSpanned = 0;
            if (direction == 0) {
                devInfo.outputPorts.push_back(portInfo);
            } else {
                devInfo.inputPorts.push_back(portInfo);
            }
        }
    }
}

void MidiDriverController::ProcessMidi1Device(snd_ctl_t *ctl, int32_t card, int32_t device)
{
    HDF_LOGI("%{public}s: Start processing MIDI1 device - Card: %{public}d, Device: %{public}d",
             __func__, card, device);
    DeviceInfo devInfo;
    devInfo.deviceId = MakeDeviceId(card);
    HDF_LOGD("%{public}s: Generated device ID: %{public}" PRId64, __func__, devInfo.deviceId);
    devInfo.devfile = MakeDeviceFileName(card, device);
    HDF_LOGD("%{public}s: Device file: %{public}s", __func__, devInfo.devfile.c_str());
    devInfo.card = card;
    devInfo.device = device;
    devInfo.is_ump = false;

    ReadVendorIdAndProductId(card, devInfo.idVendor, devInfo.idProduct);
    HDF_LOGD("%{public}s: Vendor ID: %{public}s, Product ID: %{public}s",
             __func__, devInfo.idVendor.c_str(), devInfo.idProduct.c_str());
    ReadDeviceName(card, devInfo.deviceName);
    PopulateMidi1Ports(ctl, device, devInfo);

    deviceList_.push_back(devInfo);
    HDF_LOGI("%{public}s: Added device to list - Total devices: %{public}zu",
             __func__, deviceList_.size());

    HDF_LOGI("%{public}s Card: %{public}d, device:%{public}d idVendor:%{public}s, idProduct:%{public}s,",
        __func__, devInfo.card, devInfo.device, devInfo.idVendor.c_str(), devInfo.idProduct.c_str());
}

void MidiDriverController::ProcessMidi1Card(int32_t card)
{
    HDF_LOGI("%{public}s: Start processing MIDI1 card: %{public}d", __func__, card);
    std::string card_str = "hw:" + std::to_string(card);
    HDF_LOGD("%{public}s: Opening ALSA control for card: %{public}s", __func__, card_str.c_str());
    snd_ctl_t *ctl = nullptr;
    int openResult = ::snd_ctl_open(&ctl, card_str.c_str(), 0);
    if (openResult < 0) {
        HDF_LOGE("%{public}s: Failed to open ALSA control for card %{public}s, error: %{public}d",
                 __func__, card_str.c_str(), openResult);
        return;
    }
    HDF_LOGD("%{public}s: Successfully opened ALSA control", __func__);
    int32_t device = -1;
    int deviceCount = 0;
    while (::snd_ctl_rawmidi_next_device(ctl, &device) >= 0 && device >= 0) {
        HDF_LOGD("%{public}s: Processing device %{public}d on card %{public}d",
                 __func__, device, card);
        ProcessMidi1Device(ctl, card, device);
        deviceCount++;
    }

    HDF_LOGD("%{public}s: Found %{public}d MIDI devices on card %{public}d",
             __func__, deviceCount, card);
    ::snd_ctl_close(ctl);
    HDF_LOGI("%{public}s: Finished processing MIDI1 card: %{public}d, total devices: %{public}d",
             __func__, card, deviceCount);
}

void MidiDriverController::EnumerationDeviceMidi1()
{
    HDF_LOGI("%{public}s EnumerationDeviceMidi1 Start,", __func__);
    int32_t card = -1;
    while (::snd_card_next(&card) >= 0 && card >= 0) {
        ProcessMidi1Card(card);
    }
}

int32_t MidiDriverController::GetDeviceList(std::vector<MidiDeviceInfo> &deviceList)
{
    std::lock_guard<std::mutex> lock(deviceListMutex_);
    std::vector<DeviceInfo> oldDeviceList = deviceList_;
    deviceList_.clear();
    std::vector<MidiDeviceInfo> deviceInfos;
    EnumerationDeviceMidi1();
    deviceList = MakeMidiDeviceInfos(deviceList_);
    CleanupRemovedDevices(oldDeviceList);
    return HDF_SUCCESS;
}

std::shared_ptr<MidiDeviceBase> MidiDriverController::GetDeviceDriver(int64_t deviceId)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it != activeDrivers_.end()) {
        return it->second;
    }
    return nullptr;
}

int32_t MidiDriverController::OpenDevice(int64_t deviceId)
{
    std::lock_guard<std::mutex> listLock(deviceListMutex_);
    std::lock_guard<std::mutex> mapLock(deviceMapMutex_);
    if (activeDrivers_.find(deviceId) != activeDrivers_.end()) {
        return HDF_FAILURE; // Already open
    }
    ssize_t devIndex = -1;
    for (size_t i = 0; i < deviceList_.size(); i++) {
        if (deviceList_[i].deviceId == deviceId) {
            devIndex = static_cast<ssize_t>(i);
            break;
        }
    }
    if (devIndex == -1) {
        return HDF_FAILURE;
    }
    const auto& info = deviceList_[static_cast<size_t>(devIndex)];
    std::shared_ptr<MidiDeviceBase> driver;
    if (info.is_ump) {
        return HDF_FAILURE;
    } else {
        driver = std::make_shared<Midi1Device>(info);
    }
    activeDrivers_[deviceId] = driver;
    return HDF_SUCCESS;
}

int32_t MidiDriverController::CloseDevice(int64_t deviceId)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it == activeDrivers_.end()) {
        return HDF_FAILURE;
    }
    activeDrivers_.erase(it);
    return HDF_SUCCESS;
}

int32_t MidiDriverController::OpenInputPort(int64_t deviceId, uint32_t portId,
    const sptr<IMidiCallback> &dataCallback)
{
    auto driver = GetDeviceDriver(deviceId);
    if (!driver) return HDF_FAILURE;
    return driver->OpenInputPort(portId, dataCallback);
}

int32_t MidiDriverController::CloseInputPort(int64_t deviceId, uint32_t portId)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it == activeDrivers_.end()) return HDF_FAILURE;
    return it->second->CloseInputPort(portId);
}

int32_t MidiDriverController::OpenOutputPort(int64_t deviceId, uint32_t portId)
{
    auto driver = GetDeviceDriver(deviceId);
    if (!driver) return HDF_FAILURE;
    return driver->OpenOutputPort(portId);
}

int32_t MidiDriverController::CloseOutputPort(int64_t deviceId, uint32_t portId)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it == activeDrivers_.end()) return HDF_FAILURE;
    return it->second->CloseOutputPort(portId);
}

int32_t MidiDriverController::SendMidiMessages(int64_t deviceId, uint32_t portId,
    const std::vector<MidiMessage> &messages)
{
    std::lock_guard<std::mutex> lock(deviceMapMutex_);
    auto it = activeDrivers_.find(deviceId);
    if (it == activeDrivers_.end()) return HDF_FAILURE;
    return it->second->SendMidiMessages(portId, messages);
}
} // namespace V1_0
} // namespace Midi
} // namespace HDI
} // namespace OHOS