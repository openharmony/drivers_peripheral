# Camera

## 概述

OpenHarmony相机驱动框架模型对上实现相机HDI（Hardware Device Interface）接口，对下实现相机Pipeline模型，管理相机各个硬件设备。
该驱动框架模型内部分为三层，依次为HDI实现层、框架层和设备适配层，各层基本概念如下：

+ HDI实现层：实现OHOS（OpenHarmony Operation System）相机标准南向接口。
+ 框架层：对接HDI实现层的控制、流的转发，实现数据通路的搭建，管理相机各个硬件设备等功能。
+ 设备适配层：屏蔽底层芯片和OS（Operation System）差异，支持多平台适配。    

**图 1**  Camera驱动模块架构图


　　　　　　　　![](figures/Camera模块驱动模型.png)

## 目录

- Camera模块目录表如下：

  ```
  /drivers/peripheral/camera
      ├── hal                         # camera模块的hal层代码
      │   ├── adapter                 # camera hal平台适配层的实现
      │   ├── buffer_manager          # camera hal统一的Buffer管理
      │   ├── device_manager          # 提供camera hal层设备管理能力，包括设备枚举、设备能力查询等
      │   ├── hdi_impl                # camera hal HDI的具体实现
      │   ├── include                 # camera hal层内部的头文件
      │   ├── init                    # camera hal层HDI接口使用样例实现
      │   ├── pipeline_core           # camera hal层pipeline核心代码 
      │   ├── test                    # camera hal层测试代码实现
      │   └── utils                   # camera hal层工具类代码，目前提供的是watchdog
      ├── hal_c                       # 提供C实现的HAL接口
      │   ├── hdi_cif                 # C实现的HDI接口适配代码
      │   └── include                 # C形式的HDI接口
      └── interfaces                  # camera hal对上层服务提供的驱动能力接口
          ├── hdi_ipc                 # IPC模式的HDI实现
          ├── hdi_passthrough         # 直通模式的HDI实现
          └── include                 # camera hal对外提供的HDI定义
  ```

  

## 接口说明

- icamera_device.h

  | 功能描述                     | 接口名称                                                     |
  | ---------------------------- | ------------------------------------------------------------ |
  | 获取流控制器                 | CamRetCode GetStreamOperator(<br/>    const OHOS::sptr\<IStreamOperatorCallback\> &callback,<br/>    OHOS::sptr\<IStreamOperator\> &streamOperator) |
  | 更新设备控制参数             | CamRetCode UpdateSettings(const std::shared_ptr\<CameraSetting\> &settings) |
  | 设置Result回调模式和回调函数 | CamRetCode SetResultMode(const ResultCallbackMode &mode)     |
  | 获取使能的ResultMeta         | CamRetCode GetEnabledResults(std::vector\<MetaType\> &results) |
  | 使能具体的ResultMeta         | CamRetCode EnableResult(const std::vector\<MetaType\> &results) |
  | 禁止具体的ResultMeta         | CamRetCode DisableResult(const std::vector\<MetaType\> &results) |
  | 关闭Camera设备               | void Close()                                                 |

- icamera_device_callback.h

  | 功能描述                                                   | 接口名称                                                     |
  | ---------------------------------------------------------- | ------------------------------------------------------------ |
  | 设备发生错误时调用，由调用者实现，用于返回错误信息给调用者 | void OnError(ErrorType type, int32_t errorCode)              |
  | 上报camera设备相关的metadata的回调                         | void OnResult(uint64_t timestamp, const std::shared_ptr\<CameraMetadata\> &result) |


- icamera_host.h

  | 功能描述                       | 接口名称                                                     |
  | ------------------------------ | ------------------------------------------------------------ |
  | 设置ICameraHost回调接口        | CamRetCode SetCallback(const OHOS::sptr\<ICameraHostCallback\> &callback) |
  | 获取当前可用的Camera设备ID列表 | CamRetCode GetCameraIds(std::vector\<std::string\> &cameraIds) |
  | 获取Camera设备能力集合         | CamRetCode GetCameraAbility(const std::string &cameraId,<br/>    std::shared_ptr\<CameraAbility\> &ability) |
  | 打开Camera设备                 | CamRetCode OpenCamera(const std::string &cameraId,<br/>    const OHOS::sptr\<ICameraDeviceCallback\> &callback,<br/>    OHOS::sptr\<ICameraDevice\> &device) |
  | 打开或关闭闪光灯               | CamRetCode SetFlashlight(const std::string &cameraId, bool &isEnable) |

- icamera_host_callback.h

  | 功能描述               | 接口名称                                                     |
  | ---------------------- | ------------------------------------------------------------ |
  | Camera设备状态变化上报 | void OnCameraStatus(const std::string &cameraId, CameraStatus status) |
  | 闪光灯状态变化回调     | void OnFlashlightStatus(const std::string &cameraId, FlashlightStatus status) |

- ioffline_stream_operator.h

  | 功能描述       | 接口名称                                                     |
  | -------------- | ------------------------------------------------------------ |
  | 取消捕获请求   | CamRetCode CancelCapture(int captureId)                      |
  | 释放流         | CamRetCode ReleaseStreams(const std::vector\<int\> &streamIds) |
  | 释放所有离线流 | CamRetCode Release()                                         |

- istream_operator.h

  | 功能描述                         | 接口名称                                                     |
  | -------------------------------- | ------------------------------------------------------------ |
  | 查询是否支持添加参数对应的流     | CamRetCode IsStreamsSupported(<br/>    OperationMode mode,<br/>    const std::shared_ptr\<CameraMetadata> &modeSetting,<br/>    const std::vector\<std::shared_ptr\<StreamInfo\>\> &info,<br/>    StreamSupportType &type) |
  | 创建流                           | CamRetCode CreateStreams(const std::vector\<std::shared_ptr\<StreamInfo\>\> &streamInfos) |
  | 释放流                           | CamRetCode ReleaseStreams(const std::vector\<int\> &streamIds) |
  | 配置流                           | CamRetCode CommitStreams(OperationMode mode,<br/>    const std::shared_ptr\<CameraMetadata\> &modeSetting) |
  | 获取流的属性                     | CamRetCode GetStreamAttributes(<br/>    std::vector\<std::shared_ptr\<StreamAttribute\>\> &attributes) |
  | 绑定生产者句柄和指定流           | CamRetCode AttachBufferQueue(int streamId, const OHOS::sptr\<OHOS::IBufferProducer\> &producer) |
  | 解除生产者句柄和指定流的绑定关系 | CamRetCode DetachBufferQueue(int streamId)                   |
  | 捕获图像                         | CamRetCode Capture(int captureId,<br/>    const std::shared_ptr\<CaptureInfo\> &info, bool isStreaming) |
  | 取消捕获                         | CamRetCode CancelCapture(int captureId)                      |
  | 将指定流转换成离线流             | CamRetCode ChangeToOfflineStream(const std::vector\<int\> &streamIds,<br/>    OHOS::sptr\<IStreamOperatorCallback\> &callback,<br/>    OHOS::sptr\<IOfflineStreamOperator\> &offlineOperator) |

- istream_operator_callback.h

  | 功能描述                                 | 接口名称                                                     |
  | ---------------------------------------- | ------------------------------------------------------------ |
  | 捕获开始回调，在捕获开始时调用           | void OnCaptureStarted(int32_t captureId, const std::vector\<int32_t\> &streamIds) |
  | 捕获结束回调，在捕获结束时调用           | void OnCaptureEnded(int32_t captureId,<br/>    const std::vector\<std::shared_ptr\<CaptureEndedInfo\>\> &infos) |
  | 捕获错误回调，在捕获过程中发生错误时调用 | void OnCaptureError(int32_t captureId,<br/>    const std::vector\<std::shared_ptr\<CaptureErrorInfo\>\> &infos) |
  | 帧捕获回调                               | void OnFrameShutter(int32_t captureId,<br/>    const std::vector\<int32_t\> &streamIds, uint64_t timestamp) |



## 使用方法

在/drivers/peripheral/camera/hal/init目录下有一个关于Camera的demo，该demo可以完成Camera的预览，拍照等基础功能。下面我们就以此demo为例讲述怎样用HDI接口去编写预览PreviewOn()和拍照CaptureOn()的用例，可参考[ohos_camera_demo](https://gitee.com/openharmony/drivers_peripheral/tree/master/camera/hal/init)。

1. 在main函数中构造一个CameraDemo 对象，该对象中有对Camera初始化、启停流、释放等控制的方法。下面mainDemo->InitSensors()函数为初始化CameraHost，mainDemo->InitCameraDevice()函数为初始化CameraDevice。

   ```
   int main(int argc, char** argv)
   {
       RetCode rc = RC_OK;
       auto mainDemo = std::make_shared<CameraDemo>();
       rc = mainDemo->InitSensors(); // 初始化CameraHost
       if (rc == RC_ERROR) {
           CAMERA_LOGE("main test: mainDemo->InitSensors() error\n");
           return RC_ERROR;
       }
   
       rc = mainDemo->InitCameraDevice(); // 初始化CameraDevice
       if (rc == RC_ERROR) {
           CAMERA_LOGE("main test: mainDemo->InitCameraDevice() error\n");
           return RC_ERROR;
       }
   
       rc = PreviewOn(0, mainDemo); // 配流和启流
       if (rc != RC_OK) {
           CAMERA_LOGE("main test: PreviewOn() error demo exit");
           return RC_ERROR;
       }
   
       ManuList(mainDemo, argc, argv); // 打印菜单到控制台
   
       return RC_OK;
   }
   ```

   初始化CameraHost函数实现如下，这里调用了HDI接口ICameraHost::Get()去获取demoCameraHost，并对其设置回调函数。

   ```
   RetCode CameraDemo::InitSensors()
   {
       demoCameraHost_ = ICameraHost::Get(DEMO_SERVICE_NAME);
       if (demoCameraHost_ == nullptr) {
           CAMERA_LOGE("demo test: ICameraHost::Get error");
           return RC_ERROR;
       }
   
       hostCallback_ = new CameraHostCallback();
       rc = demoCameraHost_->SetCallback(hostCallback_);
       return RC_OK;
   }
   ```

   初始化CameraDevice函数实现如下，这里调用了GetCameraIds(cameraIds)，GetCameraAbility(cameraId, ability)，OpenCamera(cameraIds.front(), callback, demoCameraDevice_)等接口实现了demoCameraHost的获取。

   ```
   RetCode CameraDemo::InitCameraDevice()
   {
       (void)demoCameraHost_->GetCameraIds(cameraIds_);
       const std::string cameraId = cameraIds_.front();
       demoCameraHost_->GetCameraAbility(cameraId, ability_);
   
       sptr<CameraDeviceCallback> callback = new CameraDeviceCallback();
       rc = demoCameraHost_->OpenCamera(cameraIds_.front(), callback, demoCameraDevice_);
       return RC_OK;
   }   
   ```

2. PreviewOn()接口包含配置流、开启预览流和启动Capture动作。该接口执行完成后Camera预览通路已经开始运转并开启了两路流，一路流是preview，另外一路流是capture或者video，两路流中仅对preview流进行capture动作。

   ```
   static RetCode PreviewOn(int mode, const std::shared_ptr<CameraDemo> &mainDemo)
   {
        rc = mainDemo->StartPreviewStream(); // 配置preview流
        if (mode == 0) {
           rc = mainDemo->StartCaptureStream(); // 配置capture流
        } else {
           rc = mainDemo->StartVideoStream(); // 配置video流
        }
   
        rc = mainDemo->CaptureOn(STREAM_ID_PREVIEW, CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW); // 将preview流capture
        return RC_OK;
   }           
   ```

   StartCaptureStream()、StartVideoStream()和StartPreviewStream()接口都会调用CreateStream()接口，只是传入的参数不同。

   ```
   RetCode CameraDemo::StartVideoStream()
   {
       RetCode rc = RC_OK;
       if (!isVideoOn_) {
           isVideoOn_ = true;
           rc = CreateStream(STREAM_ID_VIDEO, streamCustomerVideo_, VIDEO); // 如需启preview或者capture流更改该接口参数即可。
       }
       return RC_OK;
   }
   ```

   CreateStream()方法调用HDI接口去配置和创建流，首先调用HDI接口去获取StreamOperation对象，然后创建一个StreamInfo。调用CreateStreams()和CommitStreams()实际创建流并配置流。

   ```
   RetCode CameraDemo::CreateStreams()
   {
       std::vector<std::shared_ptr<StreamInfo>> streamInfos;
       GetStreamOpt(); // 获取StreamOperator对象        
       
       rc = streamOperator_->CreateStreams(streamInfos); // 创建流    
       rc = streamOperator_->CommitStreams(Camera::NORMAL, ability_);
        
       return RC_OK;
   }
   ```
   
   CaptureOn()接口调用streamOperator的Capture()方法获取Camera数据并轮转buffer，拉起一个线程接收相应类型的数据。
   
   ```
   RetCode CameraDemo::CaptureOn(const int streamId, const int captureId, CaptureMode mode)
   {
       std::shared_ptr<Camera::CaptureInfo> captureInfo = std::make_shared<Camera::CaptureInfo>(); // 创建并填充CaptureInfo
       captureInfo->streamIds_ = {streamId};
       captureInfo->captureSetting_ = ability_;
       captureInfo->enableShutterCallback_ = false;
   
       int rc = streamOperator_->Capture(captureId, captureInfo, true); // 实际capture开始，buffer轮转开始
       if (mode == CAPTURE_PREVIEW) {
           streamCustomerPreview_->ReceiveFrameOn(nullptr); // 创建预览线程接收递上来的buffer
       } else if (mode == CAPTURE_SNAPSHOT) {
           streamCustomerCapture_->ReceiveFrameOn([this](void* addr, const uint32_t size) { // 创建capture线程通过StoreImage回调接收递上来的buffer
               StoreImage(addr, size);
           });
       } else if (mode == CAPTURE_VIDEO) {
           OpenVideoFile();
           streamCustomerVideo_->ReceiveFrameOn([this](void* addr, const uint32_t size) {// 创建Video线程通过StoreVideo回调接收递上来的buffer
               StoreVideo(addr, size);
           });
       }
       return RC_OK;
   }
   ```
   
3. ManuList()函数从控制台通过fgets()接口获取字符，不同字符所对应demo支持的功能不同，并打印出该demo所支持功能的菜单。

   ```
   static void ManuList(const std::shared_ptr<CameraDemo> &mainDemo,
       const int argc, char** argv)
   {
       int idx, c;
       int awb = 1;
       constexpr char shortOptions[] = "h:cwvaqof:";
       c = getopt_long(argc, argv, shortOptions, longOptions, &idx);
       while(1) {
           switch (c) {
               case 'h':
                   c = PutMenuAndGetChr(); // 打印菜单
                   break;                
               case 'f':
                   FlashLightTest(mainDemo); // 手电筒功能测试
                   c = PutMenuAndGetChr();
                   break;
               case 'o':
                   OfflineTest(mainDemo); // Offline功能测试
                   c = PutMenuAndGetChr();
                   break;
               case 'c':
                   CaptureTest(mainDemo); // Capture功能测试
                   c = PutMenuAndGetChr();
                   break;
               case 'w': // AWB功能测试
                   if (awb) {
                       mainDemo->SetAwbMode(OHOS_CAMERA_AWB_MODE_INCANDESCENT);
                   } else {
                       mainDemo->SetAwbMode(OHOS_CAMERA_AWB_MODE_OFF);
                   }
                   awb = !awb;
                   c = PutMenuAndGetChr();
                   break;
               case 'a': // AE功能测试
                   mainDemo->SetAeExpo();
                   c = PutMenuAndGetChr();
                   break;
               case 'v': // Video功能测试
                   VideoTest(mainDemo);
                   c = PutMenuAndGetChr();
                   break;
               case 'q': // 退出demo
                   PreviewOff(mainDemo);
                   mainDemo->QuitDemo();
                   exit(EXIT_SUCCESS);
   
               default:
                   CAMERA_LOGE("main test: command error please retry input command");
                   c = PutMenuAndGetChr();
                   break;
           }
       }
   }
   ```
   

PutMenuAndGetChr()接口打印了demo程序的菜单，并调用fgets()等待从控制台输入命令，内容如下：

``` 
   static int PutMenuAndGetChr(void)
   {
       constexpr uint32_t inputCount = 50;
       int c = 0;
       char strs[inputCount];
       Usage(stdout);
       CAMERA_LOGD("pls input command(input -q exit this app)\n");
       fgets(strs, inputCount, stdin);
   
       for (int i = 0; i < inputCount; i++) {
           if (strs[i] != '-') {
               c = strs[i];
               break;
           }
       }
       return c;
   }
```

控制台输出菜单详情如下：

```
   "Options:\n"
   "-h | --help          Print this message\n"
   "-o | --offline       stream offline test\n"
   "-c | --capture       capture one picture\n"
   "-w | --set WB        Set white balance Cloudy\n"
   "-v | --video         capture Video of 10s\n"
   "-a | --Set AE        Set Auto exposure\n"
   "-f | --Set Flashlight        Set flashlight ON 5s OFF\n"
   "-q | --quit          stop preview and quit this app\n");
```



## 相关链接
　　[驱动子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

　　[vendor_hisilicon/tree/master/Hi3516DV300/hdf_config](https://gitee.com/openharmony/vendor_hisilicon/blob/master/README_zh.md)

　　 

