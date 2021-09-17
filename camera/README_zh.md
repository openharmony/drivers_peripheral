# Camera<a name="ZH-CN_TOPIC_0000001078436908"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
-   [接口说明](#section1564411661810)
-   [使用说明](#section19806524151819)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

HarmonyOS 相机驱动框架模型对上实现相机HDI接口，对下实现相机Pipeline模型，管理相机各个硬件设备。
各层的基本概念如下：

1.  HDI实现层，对上实现OHOS相机标准南向接口。

2.  框架层，对接HDI实现层的控制、流的转发，实现数据通路的搭建、管理相机各个硬件设备等功能。

3.  适配层，屏蔽底层芯片和OS差异，支持多平台适配。

**图 1**  Camera驱动模块架构图<a name="fig14142101381112"></a>


![](figures/logic-view-of-modules-related-to-this-repository_zh.png)


## 目录<a name="section161941989596"></a>


```
/drivers/peripheral/input
    .
    ├── hal                         # camera模块的hal层代码
    │   ├── adapter                 # camera模块平台适配层的实现
    │   ├── buffer_manager
    │   ├── device_manager
    │   ├── hdi_impl
    │   ├── include
    │   ├── init                     # HDI接口使用样例实现
    │   ├── pipeline_core
    │   ├── test                    # 模块测试代码实现
    │   └── utils
    ├── hal_c
    │   ├── hdi_cif
    │   └── include
    └── interfaces                # camera模块对上层服务提供的驱动能力接口
        └── include               # camera模块对外提供的接口定义


```

## 接口说明<a name="section1564411661810"></a>





<body link="#0563C1" vlink="#954F72">

<table border=0 cellpadding=0 cellspacing=0 width=1119 style='border-collapse:
 collapse;table-layout:fixed;width:839pt'>
 <col width=119 style='mso-width-source:userset;mso-width-alt:3797;width:89pt'>
 <col width=568 style='mso-width-source:userset;mso-width-alt:18176;width:426pt'>
 <col width=363 style='mso-width-source:userset;mso-width-alt:11605;width:272pt'>
 <col width=69 style='width:52pt'>
 <tr height=19 style='height:14.0pt'>
  <td height=19 width=119 style='height:14.0pt;width:89pt'>头文件</td>
  <td width=568 style='width:426pt'>接口名称</a></td>
  <td width=363 style='width:272pt'>功能描述</a></td>
 </tr>
 <tr height=93 style='height:70.0pt'>
  <td rowspan=10 height=728 class=xl66 style='height:546.0pt'>icamera_device.h</td>
  <td class=xl65 width=568 style='width:426pt'>CamRetCode
  IsStreamsSupported(<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OperationMode mode,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CameraMetadata&gt; &amp;modeSetting,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;StreamInfo&gt; &amp;info,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>StreamSupportType &amp;type)</td>
  <td>查询是否支持添加参数对应的流</td>
 </tr>
 <tr height=75 style='height:56.0pt'>
  <td height=75 style='height:56.0pt'>CamRetCode CreateStreams(const
  std::vector&lt;std::shared_ptr&lt;StreamInfo&gt;&gt; &amp;streamInfo<span
  style='display:none'>s)</span></td>
  <td class=xl65 width=363 style='width:272pt'>创建流<br>
    <span style='mso-spacerun:yes'>&nbsp;</span>此函数接口依据输入的流信息创建流，调用该接口之前需先通过
  {@link IsStreamsSupported} 查询HAL是否支持要创建的流</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 style='height:14.0pt'>CamRetCode ReleaseStreams(const
  std::vector&lt;int&gt; &amp;streamIds)</td>
  <td>释放流</td>

 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  CommitStreams(OperationMode mode,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CameraMetadata&gt; &amp;modeSetting)</td>
  <td class=xl65 width=363 style='width:272pt'>配置流<br>
    本接口需在调用{@link CreateStreams}创建流之后调用</td>

 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  GetStreamAttributes(<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>std::vector&lt;std::shared_ptr&lt;StreamAttribute&gt;&gt;
  &amp;attributes)</td>
  <td>获取流的属性</td>

 </tr>
 <tr height=168 style='height:126.0pt'>
  <td height=168 class=xl65 width=568 style='height:126.0pt;width:426pt'>CamRetCode
  AttachBufferQueue(int streamId, const OHOS::sptr&lt;OHOS::IBufferProducer&gt;
  &amp;producer)</td>
  <td class=xl65 width=363 style='width:272pt'>绑定生产者句柄和指定流<br>
    <br>
    如果在{@link CreateStreams}创建流时已经指定了生产者句柄，则不需要调用该接口。如果需要重新绑定，<br>
    <span
  style='mso-spacerun:yes'>&nbsp;</span>对于一些IOT设备，可能不需要或者不支持预览流的图像数据缓存流转，那么不需要绑定生产者句柄，<br>
    此时在创建流时{@link CreateStreams} 的 {@link StreamInfo} 参数的生产者句柄bufferQueue_为空，而<br>
    <span style='mso-spacerun:yes'>&nbsp;</span>tunneledMode_需设置为false。</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  DetachBufferQueue(int streamId)</td>
  <td>解除生产者句柄和指定流的绑定关系</td>

 </tr>
 <tr height=205 style='height:154.0pt'>
  <td height=205 class=xl65 width=568 style='height:154.0pt;width:426pt'>CamRetCode
  Capture(int captureId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CaptureInfo&gt; &amp;info,<span
  style='mso-spacerun:yes'>&nbsp; </span>bool isStreaming)</td>
  <td class=xl65 width=363 style='width:272pt'>捕获图像<br>
    <span style='mso-spacerun:yes'>&nbsp;</span>本接口必须在调用 {@link CommitStreams}
  配置流之后调用。<br>
    <span
  style='mso-spacerun:yes'>&nbsp;</span>图像捕获有两种模式，分别是连续捕获和单次捕获。连续捕获即触发之后模块内部进行连续的捕获，<br>
    消费者可以连续收到图像数据，不需要多次调用本接口，若再次调用了本接口，<br>
    <span
  style='mso-spacerun:yes'>&nbsp;</span>则停止当前捕获，更新捕获信息，再进行一次新的捕获，多用于预览、录像或者连拍场景。<br>
    <span style='mso-spacerun:yes'>&nbsp;</span>单次捕获即触发之后只捕获一帧图像数据，用于单次拍照场景</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  CancelCapture(int captureId)</td>
  <td>取消捕获</td>

 </tr>
 <tr height=56 style='height:42.0pt'>
  <td height=56 class=xl65 width=568 style='height:42.0pt;width:426pt'>CamRetCode
  ChangeToOfflineStream(const std::vector&lt;int&gt; &amp;streamIds,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OHOS::sptr&lt;IStreamOperatorCallback&gt; &amp;callback,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OHOS::sptr&lt;IOfflineStreamOperator&gt; &amp;offlineOperator)</td>
  <td class=xl65 width=363 style='width:272pt'>将指定流转换成离线流</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td rowspan=2 height=38 class=xl66 style='height:28.0pt'>icamera_device_callback.h</td>
  <td class=xl65 width=568 style='width:426pt'>void OnError(ErrorType type,
  int32_t errorCode)</td>
  <td colspan=2 style='mso-ignore:colspan'>设备发生错误时调用，由调用者实现，用于返回错误信息给调用者</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>void
  OnResult(uint64_t timestamp, const std::shared_ptr&lt;CameraMetadata&gt;
  &amp;result)</td>
  <td class=xl65 width=363 style='width:272pt'>上报camera设备相关的metadata的回调</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td rowspan=5 height=150 class=xl66 style='height:112.0pt'>icamera_host.h</td>
  <td class=xl65 width=568 style='width:426pt'>CamRetCode SetCallback(const
  OHOS::sptr&lt;ICameraHostCallback&gt; &amp;callback)</td>
  <td>设置ICameraHost回调接口</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 style='height:14.0pt'>CamRetCode
  GetCameraIds(std::vector&lt;std::string&gt; &amp;cameraIds)</td>
  <td>获取当前可用的Camera设备ID列表</td>

 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  GetCameraAbility(const std::string &amp;cameraId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>std::shared_ptr&lt;CameraAbility&gt; &amp;ability)</td>
  <td>获取Camera设备能力集合</td>

 </tr>
 <tr height=56 style='height:42.0pt'>
  <td height=56 class=xl65 width=568 style='height:42.0pt;width:426pt'>CamRetCode
  OpenCamera(const std::string &amp;cameraId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const OHOS::sptr&lt;ICameraDeviceCallback&gt; &amp;callback,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OHOS::sptr&lt;ICameraDevice&gt; &amp;device)</td>
  <td>打开Camera设备</td>

 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  SetFlashlight(const std::string &amp;cameraId, bool &amp;isEnable)</td>
  <td>打开或关闭闪光灯</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td rowspan=2 height=38 class=xl66 style='height:28.0pt'>icamera_host_callback.h</td>
  <td class=xl65 width=568 style='width:426pt'>void OnCameraStatus(const
  std::string &amp;cameraId, CameraStatus status)</td>
  <td>Camera设备状态变化上报</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>void
  OnFlashlightStatus(const std::string &amp;cameraId, FlashlightStatus status)</td>
  <td>闪光灯状态变化回调</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td rowspan=3 height=57 class=xl66 style='height:42.0pt'>ioffline_stream_operator.h</td>
  <td class=xl65 width=568 style='width:426pt'><span
  style='mso-spacerun:yes'>&nbsp;</span>CamRetCode CancelCapture(int captureId)</td>
  <td>取消捕获请求</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  ReleaseStreams(const std::vector&lt;int&gt; &amp;streamIds)</td>
  <td>释放流</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  Release()</td>
  <td>释放所有离线流</td>
 </tr>
 <tr height=93 style='height:70.0pt'>
  <td rowspan=10 height=783 class=xl66 style='height:588.0pt'>istream_operator.h</td>
  <td class=xl65 width=568 style='width:426pt'>CamRetCode
  IsStreamsSupported(<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OperationMode mode,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CameraMetadata&gt; &amp;modeSetting,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;StreamInfo&gt; &amp;info,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>StreamSupportType &amp;type)</td>
  <td>查询是否支持添加参数对应的流</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  CreateStreams(const std::vector&lt;std::shared_ptr&lt;StreamInfo&gt;&gt;
  &amp;streamInfos)</td>
  <td>创建流</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  ReleaseStreams(const std::vector&lt;int&gt; &amp;streamIds)</td>
  <td>释放流</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  CommitStreams(OperationMode mode,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CameraMetadata&gt; &amp;modeSetting)</td>
  <td class=xl65 width=363 style='width:272pt'><br>
    配置流</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  GetStreamAttributes(<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>std::vector&lt;std::shared_ptr&lt;StreamAttribute&gt;&gt;
  &amp;attributes)</td>
  <td>获取流的属性</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>CamRetCode
  AttachBufferQueue(int streamId, const OHOS::sptr&lt;OHOS::IBufferProducer&gt;
  &amp;producer)</td>
  <td>绑定生产者句柄和指定流</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'><span
  style='mso-spacerun:yes'>&nbsp;</span>CamRetCode DetachBufferQueue(int
  streamId)</td>
  <td>解除生产者句柄和指定流的绑定关系</td>
 </tr>
 <tr height=429 style='height:322.0pt'>
  <td height=429 class=xl65 width=568 style='height:322.0pt;width:426pt'>CamRetCode
  Capture(int captureId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::shared_ptr&lt;CaptureInfo&gt; &amp;info,<span
  style='mso-spacerun:yes'>&nbsp; </span>bool isStreaming)</td>
  <td class=xl65 width=363 style='width:272pt'>捕获图像<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>*<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>* 本接口必须在调用
  {@link CommitStreams} 配置流之后调用。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>*
  图像捕获有两种模式，分别是连续捕获和单次捕获。连续捕获即触发之后模块内部进行连续的捕获，<br>
    	 * 消费者可以连续收到图像数据，不需要多次调用本接口，若再次调用了本接口，<br>
    	 * 则停止当前捕获，更新捕获信息，再进行一次新的捕获，多用于预览、录像或者连拍场景。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>*
  单次捕获即触发之后只捕获一帧图像数据，用于单次拍照场景。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>* 捕获启动时，会调用
  {@link OnCaptureStarted}来通知调用者捕获已经启动。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>* 连续捕获需调用
  {@link CancelCapture} 来停止捕获。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>* 捕获结束时，会调用
  {@link OnCaptureEnded}来通知调用者捕获的帧计数等信息。<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>* {@link
  CaptureInfo} 的 enableShutterCallback_ 使能 {@link OnFrameShutter}，使能后每次捕获触发
  {@link OnFrameShutter}<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp; </span>*
  对于多个流同时捕获的场景，本模块内部保证同时上报多路流捕获数据。</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td height=19 class=xl65 width=568 style='height:14.0pt;width:426pt'>CamRetCode
  CancelCapture(int captureId)</td>
  <td>取消捕获</td>
 </tr>
 <tr height=56 style='height:42.0pt'>
  <td height=56 class=xl65 width=568 style='height:42.0pt;width:426pt'>CamRetCode
  ChangeToOfflineStream(const std::vector&lt;int&gt; &amp;streamIds,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OHOS::sptr&lt;IStreamOperatorCallback&gt; &amp;callback,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>OHOS::sptr&lt;IOfflineStreamOperator&gt; &amp;offlineOperator)</td>
  <td>将指定流转换成离线流</td>
 </tr>
 <tr height=19 style='height:14.0pt'>
  <td rowspan=4 height=130 class=xl66 style='height:98.0pt'>istream_operator_callback.h</td>
  <td class=xl65 width=568 style='width:426pt'>void OnCaptureStarted(int32_t
  captureId, const std::vector&lt;int32_t&gt; &amp;streamIds)</td>
  <td>捕获开始回调，在捕获开始时调用</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>void
  OnCaptureEnded(int32_t captureId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::vector&lt;std::shared_ptr&lt;CaptureEndedInfo&gt;&gt;
  &amp;infos)</td>
  <td>捕获结束回调，在捕获结束时调用</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>void
  OnCaptureError(int32_t captureId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::vector&lt;std::shared_ptr&lt;CaptureErrorInfo&gt;&gt;
  &amp;infos)</td>
  <td>捕获错误回调，在捕获过程中发生错误时调用</td>
 </tr>
 <tr height=37 style='height:28.0pt'>
  <td height=37 class=xl65 width=568 style='height:28.0pt;width:426pt'>void
  OnFrameShutter(int32_t captureId,<br>
    <span style='mso-spacerun:yes'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  </span>const std::vector&lt;int32_t&gt; &amp;streamIds, uint64_t timestamp)</td>
  <td>帧捕获回调
 </tr>
 <![if supportMisalignedColumns]>
 <tr height=0 style='display:none'>
  <td width=119 style='width:89pt'></td>
  <td width=568 style='width:426pt'></td>
  <td width=363 style='width:272pt'></td>
  <td width=69 style='width:52pt'></td>
 </tr>
 <![endif]>
</table>

</body>

</html>





### 接口数量：25

### 包：

    package ohos.hdi.camera.host@1.0;

### 路径：

    interfaces/include/icamera_host.h

### 类：

    CameraHost：提供设备个数查询、能力查询和打开设备等接口；

### 函数：

```

/**
 * @brief 设置Host回调函数
 *
 * @param callback Host回调函数
 * @return CamRetCode
 */
CamRetCode SetCallback([in] ICameraHostCallback callback);

/**
 * @brief 获取当前可用的Camera设备列表
 *
 * @param ids 返回的当前可用的设备列表
 */
CamRetCode GetCameraIds([out] String[] ids);

/**
 * @brief 获取Camera的能力集
 *
 * @param cameraId 要获取的Camera设备id
 * @param ability Camera设备的能力集
 * @return CamRetCode
 * @see CameraAbility
 */
CamRetCode GetCameraAbility([in] String cameraId, [out] CameraAbility ability);

/**
 * @brief 打开Camera设备
 *
 * @param cameraId 要打开的Camera设备id
 * @param callback Camera设备的回调函数
 * @param camera 返回的Camera设备接口
 * @return CamRetCode
 * @see ICameraDeviceCallback
 * @see ICameraDevice
 */
CamRetCode OpenCamera([in] String cameraId, [in] ICameraDeviceCallback callback, [out] ICameraDevice camera);

/**
 * @brief 打开或者关闭手电筒
 *
 * @param cameraId 手电筒与之关联的Camera设备id
 * @param isEnable 闪光灯打开或者关闭
 * @return CamRetCode
 */
CamRetCode SetFlashlight[in] String cameraId, [out] boolean isEnable);

```


### 包：
    package ohos.hdi.camera.device@1.0;
### 路径：
    interfaces/include/icamera_device.h
### 类：
    CameraDevice: Camera设备控制接口;
### 函数：

    /**
     * @brief 获取流控制器
     *
     * @param callback 流回调函数
     * @param operator 返回的流控制器
     * @return CamRetCode
     */
    CamRetCode GetStreamOperator([in] IStreamOperatorCallback callback, [out] IStreamOperator operator);

    /**
     * @brief 更新设备控制参数
     *
     * @param setting Camera设置参数
     * @return CamRetCode
     */
    CamRetCode UpdateSettings(CameraSetting setting);

    /**
     * @brief 设置Result回调模式和回调函数
     *
     * @param mode Result的上报模式
     * @param callback Result的上报callback函数
     * @return CamRetCode
     */
    CamRetCode SetResultMode([in] ResultCallbackMode mode);

    /**
     * @brief 获取使能的ResultMeta
     *
     * @param results 使能的ResultMeta数组
     * @return CamRetCode
     */
    CamRetCode GetEnabledResults([out] MetaType[] results);

    /**
     * @brief 使能具体的ResultMeta
     *
     * @param results 需要使能的ResultMeta数组
     * @return CamRetCode
     */
    CamRetCode EnableResult([in] MetaType[] results);

    /**
     * @brief 禁止具体的ResultMeta
     *
     * @param results 需要禁止的ResultMeta数组
     * @return CamRetCode
     */
    CamRetCode DisableResult(in] MetaType[] results);

    /**
     * @brief 关闭Camera设备
     */
    void Close();



### 包：
    package ohos.hdi.camera.stream@1.0;
### 路径：
    interfaces/include/istream_operator.h
### 类：
    SteamOperator: 提供设备个数查询、能力查询和打开设备等接口;
### 函数：


    /**
     * @brief 查询模式和流的配置组合是否支持
     *
     * @param mode 要配置的模式
     * @param modeSettings 模式对应的参数
     * @param info 流的信息
     * @param type 配置流支持的方式
     * @return RetCode
     */
    RetCode IsStreamsSupported([in] OperationMode mode, [in] CameraMetadata modeSetting, [in] StreamInfo[] info, [out] StreamSupportType type);

     /**
     * @brief 创建流
     *
     * @param streamInfo 需要创建的流信息列表
     * @return RetCode
     */
    RetCode CreateStreams([in] StreamInfo[] streamInfo);

    /**
     * @brief 释放流
     *
     * @param streamIds 需要释放的流Id列表
     * @return RetCode
     */
    RetCode ReleaseStreams([in] int[] streamIds);

    /**
     * @brief 使能相机流的配置，并配置工作模式
     *
     * @param mode 要配置的模式
     * @param modeSetting 模式对应的参数
     * @return RetCode
     * @see OperationMode
     */
    RetCode CommitStreams([in] OperationMode mode, [in] CameraMetadata modeSetting);

    /**
     * @brief 获取所有流特征
     *
     * @param streamId  需要获取额的流id
     * @param attribute 流的属性
     * @return RetCode
     */
    RetCode GetStreamAttributes([out] StreamAttribute[] attributes);

    /**
     * @brief 关联BufferQueue
     *
     * @param streamId 需要关联的流id
     * @param producer 要关联的BufferQueue对应的producer接口
     * @return RetCode
     */
    RetCode AttachBufferQueue([in] streamId, [in] IBufferClientProducer producer);

    /**
     * @brief 取消关联BufferQueue
     *
     * @param streamId 取消关联的流id
     * @return RetCode
     */
    RetCode DetachBufferQueue([in] int streamId);

    /**
     * @brief 捕获图像
     *
     * @param captureId 标志此次捕获请求的id
    * @param info 捕获图像的参数信息，如果数组中的info存在多个，则表明是batch模式，连续捕获多帧
     * @param isStreaming 是否连续捕获
     * @see StreamAttribute
     * @return RetCode
     */
    RetCode Capture([in] int captureId, [in] CaptureInfo[] info, [in] bool isStreaming);

    /**
     * @brief 取消图像捕获
     *
     * @return RetCode
     */
    RetCode CancelCapture([in] int captureId);

    /**
     * @brief 将普通流转换成离线流
     *
     * @param streams 需要转换的普通流Id列表
     * @param callback 离线流的callback
     * @param offlineOperator 离线流的控制器
     * @return RetCode
     */
    RetCode ChangeToOfflineStream([in] int[] streamIds, [in]IStreamOperatorCallback callback, [out]IOfflineStreamOperator offlineOperator);`

### 包：
    package ohos.hdi.camera.stream@1.0;
### 路径：
    interfaces/include/istream_operator.h
### 类：
    IOfflineStreamOperator: 离线流控制类;
### 函数：

    /**
     * @brief 取消图像捕获
     *
     * @param captureId 取消捕获的captureId
     * @return RetCode
     */
    RetCode CancelCapture([in] int captureId);

    /**
     * @brief 释放离线流资源
     *
     * @param streamIds 释放的流id列表
     * @return RetCode
     */
    RetCode ReleaseStreams([in] int[] streamIds);

    /**
     * @brief 释放IOfflineStreamOperator句柄
     *
     * @return RetCode
     */
    RetCode Release();`

## 数据结构定义

    interfaces/hdi/types.h

## 使用方法

    using namespace Camera;

### 获取CameraHost

    std::shared_ptr<Camera::CameraHost> cameraHost = Camera::CameraHost::CreateCameraHost();

### 获取配置的cameraId

    std::vector<std::string> cameraIds;
cameraHost->GetCameraIds(cameraIds); #

### 打开camera设备并获取到device

    const std::shared_ptr<Camera::ICameraDeviceCallback> callback = std::make_shared<Camera::ICameraDeviceCallback>();

    std::shared_ptr<Camera::CameraDevice> device;

    std::cout << "cameraIds.front() = " << cameraIds.front() << std::endl;

    Camera::CamRetCode rc = cameraHost->OpenCamera(cameraIds.front(), callback, device);


### 调用device的GetStreamOperator函数获取streamOperator

    std::make_shared<Camera::IStreamOperatorCallback>();
    std::shared_ptr<Camera::StreamOperator> streamOperator = nullptr;
    rc = device->GetStreamOperator(streamOperatorCallback, streamOperator);`
### 批量创建数据流
    std::vector<std::shared_ptr<Camera::StreamInfo>> streamInfos;
    std::shared_ptr<Camera::StreamInfo> streamInfo = std::make_shared<Camera::StreamInfo>();
    streamInfo->streamId_ = 1001;
    streamInfo->width_ = 1280;
    streamInfo->height_ = 720;
    streamInfo->format_ = 2;
    streamInfo->datasapce_ = 10;
    streamInfo->intent_ = Camera::PREVIEW;
    streamInfo->tunneledMode_ = 5;
    streamInfos.push_back(streamInfo);
    rc = streamOperator->CreateStreams(streamInfos);
### 配流起流
    rc = streamOperator->CommitStreams(Camera::NORMAL, nullptr);

## 相关仓<a name="section1371113476307"></a>
[驱动子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[vendor_hisilicon/tree/master/Hi3516DV300/hdf_config](https://gitee.com/openharmony/vendor_hisilicon/blob/master/README_zh.md)

drivers\_peripheral
