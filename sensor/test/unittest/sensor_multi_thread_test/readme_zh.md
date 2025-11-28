# sensor多客户端能力测试2

> 本测试用例模拟一个上游进程启动两个线程共注册4个callback订阅sensor的情况，统计每秒收到数据个数，参数可以在cmd命令中修改。<br>
> callback1，注册callbackId为GPS_CALLBACK_ID_BEGIN，订阅传感器1，频率为10毫秒，期望收到符合频率的传感器数据。<br>
> callback2，注册callbackId为GPS_CALLBACK_ID_BEGIN+1，订阅传感器2，频率为220毫秒，期望收到符合频率的传感器数据。<br>
> callback3，注册callbackId为GPS_CALLBACK_ID_BEGIN+2，订阅传感器1，频率为40毫秒，期望收到符合频率的传感器数据。<br>
> callback4，注册callbackId为GPS_CALLBACK_ID_BEGIN+3，订阅传感器2，频率为80毫秒，期望收到符合频率的传感器数据。<br>
---

## 目录

- [简介](#简介)
- [安装说明](#安装说明)
- [使用示例](#使用示例)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 简介
**图 1**  Sensor测试用例模拟图<a name="fig1292918466322"></a>
![示例图片](sensor_test.jpg)
---

## 运行用例的要领：

### 1. 编译用例

将用例编译好后，放到统一路径，在当前路径执行如下命令：

```bash
hdc target mount
hdc shell hilog -b D -D 0xD002516
hdc file send SensorMultiCallbackTest /data/SensorMultiCallbackTest
hdc shell chmod 777 /data/SensorMultiCallbackTest
hdc shell "export testSensorType=1;export testSamplingInterval=10000000;export testPrintDataFlag=false;export testTestTime=20000;/data/SensorMultiCallbackTest"
pause