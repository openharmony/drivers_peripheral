## 目录

```
/drivers/peripheral/usb/moduletest/common
├── usb_serial_device_func_test.cpp          #串口设备的测试套
├── usb_raw_api_func_test.cpp                #串口设备raw api的测试套
├── usb_net_device_func_test.cpp             #网卡设备的测试套
├── usb_compose_device_func_test.cpp         #复合逻辑设备的测试套
├── usb_raw_host_func_test.cpp               #device连接标准host时的测试套
├── usb_host_performance_test.cpp            #host性能测试套
├── usb_device_performance_test.cpp          #device性能测试套
├── scripts
│   ├── usb_raw_host_loopback.sh             #用于配合usb_raw_host_func_test测试套进行测试，在标准host上执行该脚本
│   ├── usb_watch_process.sh                 #用于监控host和divice sdk的进程信息
│   ├── usb_set_net_ip.sh                    #设置网卡设备的Ip,配合usb_net_device_func_test测试套进行测试
│   └── usb_device_loopback.sh               #用于配合usb_serial_device_func_test测试套进行测试，在device开发板上执行该脚本
```


## 环境准备

host端开发板上执行的测试套：usb_serial_device_func_test, usb_raw_api_func_test, usb_host_performance_test
device端开发板上执行的测试套：usb_raw_host_func_test, usb_net_device_func_test, usb_compose_device_func_test, usb_device_performance_test

### usb_serial_device_func_test
1. device端替换串口设备的HCB配置文件并重启，然后连接到host端开发板;
2. 在device端开发板上面执行shell脚本`usb_device_loopback.sh`;
3. 将可执行测试程序放到host端执行

### usb_net_device_func_test
1. device端替换网卡设备的HCB配置文件并重启，然后连接到host端开发板;
2. 在host运行ping程序: `host_level_ip 10.0.0.4`;
3. 将可执行测试程序放到device端执行

### usb_compose_device_func_test
1. device端替换复合逻辑设备的HCB配置文件并重启，然后连接到Ubuntu PC;
2. 在Ubuntu PC上先设置网卡IP: `sudo ifconfig enp0s6u2 10.0.0.10`;
3. Ubuntu PC上运行shell脚本`usb_raw_host_loopback.sh`;
4. 将可执行测试程序放到device端执行

### usb_raw_host_func_test
1. device端替换串口设备的HCB配置文件并重启，然后连接到Ubuntu PC;
2. 在Ubuntu PC端执行shell脚本`usb_raw_host_loopback.sh`;
3. 将可执行测试程序放到device端执行

### usb_host_performance_test
1. device端替换串口设备的HCB配置文件并重启，然后连接到host端开发板;
2. 将可执行测试程序和watch_process.sh脚本放到host端的同一目录下；
3. 在host端执行测试程序

### usb_device_performance_test
1. device端替换串口设备的HCB配置文件并重启，然后连接到Ubuntu PC;
2. 在Ubuntu PC上面打开`/dev/ttyACM0`串口;
3. 将可执行测试程序和watch_process.sh脚本放到device端的同一目录下；
4. 在device端执行测试程序


