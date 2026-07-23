# NearLink<a name="ZH-CN_TOPIC_0000001148577119"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section161941989596)
-   [Constraints](#section119744591305)
-   [Usage](#section1312121216216)
    -   [DLI APIs](#section129654513264)

-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section11660541593"></a>

The NearLink driver module provides APIs for accessing and using the NearLink short-range communication protocol, including DLI initialization, data sending and receiving, and closing the NearLink DLI.

## Directory Structure<a name="section161941989596"></a>

```
/foundation/drivers/peripheral/nearlink
├── bundle.json                              # Component description and dependency configuration
├── drivers_peripheral_nearlink.gni         # Build feature parameter configuration
├── dli                                     # DLI module
│   └── test                                # DLI test cases
└── LICENSE                                  # Copyright statement
└── bundle.json                              # Component description file
```

## Constraints<a name="section119744591305"></a>

The NearLink driver module is written in C++ and based on the DLI framework. It supports the standard system only.

## Usage<a name="section1312121216216"></a>

NearLink DLI APIs are provided. The DLI APIs include initialization, sending and receiving DLI packets, and close.

### DLI APIs<a name="section129654513264"></a>

-   Initialize the NearLink HAL:

```
/* Initialize the NearLink HAL and register the callback. */
int32_t SleHalInit(const sptr<ISleHciCallback>& callbackObj);
```

-   Send a packet:

```
/* Send a packet to the chip. */
int32_t SleSendHciPacket(const std::vector<uint8_t>& data);
```

-   Receive a packet:

```
/* Receive a packet from the chip. */
int32_t hciPacketReceived(uint32_t type, const std::vector<uint8_t> &data);
```

-   Close the NearLink DLI:

```
/* Close the NearLink DLI and release resources. */
int32_t Close();
```

## Repositories Involved<a name="section1371113476307"></a>

drivers\_peripheral\_nearlink
