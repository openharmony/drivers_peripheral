/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

 #ifndef OHOS_HDI_USB_V1_2_USBD_PORTS_H
 #define OHOS_HDI_USB_V1_2_USBD_PORTS_H
 
 #include <fcntl.h>
 #include <sys/types.h>
 #include <unistd.h>
 #include <map>
 #include <dirent.h>
 #include <vector>
 #include <mutex>
 
 #include "usb_host_data.h"
 #include "usbd.h"
 #include "v1_0/iusbd_subscriber.h"
 #include "v1_2/usb_types.h"
 #include "v2_0/iusbd_subscriber.h"
 #include "usbd_wrapper.h"
 
 namespace OHOS {
 namespace HDI {
 namespace Usb {
 namespace V1_2 {
 class UsbdPorts {
 public:
     static UsbdPorts &GetInstance();
     int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode);
     int32_t QueryPorts(std::vector<V2_0::UsbPort>& portList);
 
     int32_t UpdatePort(int32_t mode, const sptr<IUsbdSubscriber>& subscriber);
     int32_t UpdatePort(int32_t mode, const sptr<OHOS::HDI::Usb::V2_0::IUsbdSubscriber>& subscriber);
 
     int32_t SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
         UsbdSubscriber *usbdSubscribers, uint32_t len);
 
     int32_t SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
         V2_0::UsbdSubscriber *usbdSubscribers, uint32_t len);
 
     void setPortPath(const std::string &path);
 
 private:
     UsbdPorts();
     ~UsbdPorts() = default;
     UsbdPorts(const UsbdPorts &) = delete;
     UsbdPorts(UsbdPorts &&) = delete;
     UsbdPorts &operator=(const UsbdPorts &) = delete;
     UsbdPorts &operator=(UsbdPorts &&) = delete;
 
     int32_t ParseDirectory(const std::string& path, std::vector<std::string>& portIds, bool flag);
     int32_t ReadPortInfo(const std::string& portId, V2_0::UsbPort& usbPort);
     int32_t WritePortInfo(const std::string& portId, const std::string& portAttributeFilePath, std::string& data);
     int32_t OpenFile(const std::string& path, int32_t flags);
     int32_t ParsePortAttribute(const std::string& portAttributeFileName,
         const std::string& buff, V2_0::UsbPort& usbPort);
     void InitMap();
     int32_t ParsePortId(std::string& value);
     int32_t GetAttributeValue(const std::string& buff, int32_t& outEnumValue);
     void AddPort(const V2_0::UsbPort &port);
     bool IsRoleValueLegality(int32_t powerRole, int32_t dataRole);
     void GetRoleStrValue(int32_t role, std::string& strRole, bool flag);
     bool IsUpdate(const V2_0::UsbPort& usbPortInfo);
     void ReportData(const V2_0::UsbPort& usbPort, V2_0::PortInfo& portInfo);
     void ReportData(const V2_0::UsbPort& usbPort, PortInfo& portInfo);
     int32_t SetPortInfo(int32_t portId, int32_t powerRole, int32_t dataRole, V2_0::UsbPort& port);
     bool IsFileFormat(const std::string& dName);
     bool IsSupportedMode(int32_t portId);
 
     std::string path_;
     std::mutex mutex_;
     std::map<std::string, int32_t> portAttributeMap_;
     std::map<int32_t, V2_0::UsbPort> portCacheDataMap_;
 };
 } // namespace V1_2
 } // namespace Usb
 } // namespace HDI
 } // namespace OHOS
 #endif // OHOS_HDI_USB_V1_2_USBD_PORT_H
 