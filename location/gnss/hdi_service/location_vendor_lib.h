/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LOCATION_LOCATION_VENDOR_LIB_H
#define OHOS_HDI_LOCATION_LOCATION_VENDOR_LIB_H

#include <cstdint>
#include <sys/socket.h>

namespace OHOS {
namespace HDI {
namespace Location {

#define SATELLITE_NUM_MAXIMUM 128
#define APN_LENGTH_MAXIMUM 64
#define GNSS_NI_SUPPLICANT_INFO_LENGTH_MAXIMUM 256
#define GNSS_NI_NOTIFICATION_TEXT_LENGTH_MAXIMUM 2048

enum class GnssLocationValidity {
    GNSS_LOCATION_LAT_VALID = (1 << 0),
    GNSS_LOCATION_LONG_VALID = (1 << 1),
    GNSS_LOCATION_ALTITUDE_VALID = (1 << 2),
    GNSS_LOCATION_SPEED_VALID = (1 << 3),
    GNSS_LOCATION_BEARING_VALID = (1 << 4),
    GNSS_LOCATION_HORIZONTAL_ACCURACY_VALID = (1 << 5),
    GNSS_LOCATION_VERTICAL_ACCURACY_VALID = (1 << 6),
    GNSS_LOCATION_SPEED_ACCURACY_VALID = (1 << 7),
    GNSS_LOCATION_BEARING_ACCURACY_VALID = (1 << 8),
    GNSS_LOCATION_TIME_VALID = (1 << 9),
    GNSS_LOCATION_TIME_SINCE_BOOT_VALID = (1 << 10),
    GNSS_LOCATION_TIME_UNCERTAINTY_VALID = (1 << 11),
};

enum class AgnssSetidCategory {
    AGNSS_SETID_CATEGORY_NULL = 0,
    AGNSS_SETID_CATEGORY_IMSI = 1,
    AGNSS_SETID_CATEGORY_MSISDN = 2,
};

enum class AgnssRefInfoCategory {
    AGNSS_REF_INFO_CATEGORY_CELLID = 1,
    AGNSS_REF_INFO_CATEGORY_MAC = 2,
};

enum class GnssStartCategory {
    GNSS_START_CATEGORY_NORMAL = 1,
    GNSS_START_CATEGORY_GNSS_CACHE = 2,
};

enum class CellIdCategory {
    CELLID_CATEGORY_GSM = 1,
    CELLID_CATEGORY_UMTS = 2,
    CELLID_CATEGORY_LTE = 3,
    CELLID_CATEGORY_NR = 4,
};

enum class AgnssDataConnectionSetUpCategory {
    ESTABLISH_DATA_CONNECTION = 1,
    RELEASE_DATA_CONNECTION = 2
};

enum class DataConnectionState {
    DATA_CONNECTION_DISCONNECTED = 1,
    DATA_CONNECTION_CONNECTED = 2,
};

enum class AgnssCategory {
    AGNSS_CATEGORY_SUPL = 1,
    AGNSS_CATEGORY_C2K = 2
};

enum class ApnIpCategory {
    APN_CATEGORY_INVALID = 0,
    APN_CATEGORY_IPV4 = 1,
    APN_CATEGORY_IPV6 = 2,
    APN_CATEGORY_IPV4V6 = 3
};

enum class ConstellationCategory {
    CONSTELLATION_CATEGORY_UNKNOWN = 0,
    CONSTELLATION_CATEGORY_GPS = 1,
    CONSTELLATION_CATEGORY_SBAS = 2,
    CONSTELLATION_CATEGORY_GLONASS = 3,
    CONSTELLATION_CATEGORY_QZSS = 4,
    CONSTELLATION_CATEGORY_BEIDOU = 5,
    CONSTELLATION_CATEGORY_GALILEO = 6,
    CONSTELLATION_CATEGORY_IRNSS = 7,
    CONSTELLATION_CATEGORY_MAXIMUM = 8,
};

enum class GnssWorkingStatus {
    GNSS_WORKING_STATUS_NULL = 0,
    GNSS_WORKING_STATUS_NAVIGATING_BEGIN = 1,
    GNSS_WORKING_STATUS_NAVIGATING_END = 2,
    GNSS_WORKING_STATUS_POWER_ON = 3,
    GNSS_WORKING_STATUS_POWER_OFF = 4
};

enum class GnssCapabilities {
    GNSS_CAP_SUPPORT_MSB = (1 << 0),
    GNSS_CAP_SUPPORT_MSA = (1 << 1),
    GNSS_CAP_SUPPORT_GEOFENCING = (1 << 2),
    GNSS_CAP_SUPPORT_MEASUREMENTS = (1 << 3),
    GNSS_CAP_SUPPORT_NAV_MESSAGES = (1 << 4),
    GNSS_CAP_SUPPORT_GNSS_CACHE = (1 << 5),
};

enum class SatelliteAdditionalInfo {
    SATELLITES_ADDITIONAL_INFO_NULL = 0,
    SATELLITES_ADDITIONAL_INFO_EPHEMERIS_DATA_EXIST = (1 << 0),
    SATELLITES_ADDITIONAL_INFO_ALMANAC_DATA_EXIST = (1 << 1),
    SATELLITES_ADDITIONAL_INFO_USED_IN_FIX = (1 << 2),
    SATELLITES_ADDITIONAL_INFO_CARRIER_FREQUENCY_EXIST = (1 << 3),
};

enum class GnssWorkingMode {
    GNSS_WORKING_MODE_STANDALONE = 1,
    GNSS_WORKING_MODE_MS_BASED = 2,
    GNSS_WORKING_MODE_MS_ASSISTED = 3
};

enum class GnssRefInfoCategory {
    GNSS_REF_INFO_CATEGORY_TIME = 1,
    GNSS_REF_INFO_CATEGORY_GNSS_LOCATION = 2,
    GNSS_REF_INFO_CATEGORY_BEST_LOCATION = 3,
    GNSS_REF_INFO_CATEGORY_GNSS_LOCATION_EMERGENCY = 4,
    GNSS_REF_INFO_CATEGORY_BEST_LOCATION_EMERGENCY = 5,
};

enum class GnssAuxiliaryDataCategory {
    GNSS_AUXILIARY_DATA_CATEGORY_EPHEMERIS = (1 << 0),
    GNSS_AUXILIARY_DATA_CATEGORY_ALMANAC = (1 << 1),
    GNSS_AUXILIARY_DATA_CATEGORY_POSITION = (1 << 2),
    GNSS_AUXILIARY_DATA_CATEGORY_TIME = (1 << 3),
    GNSS_AUXILIARY_DATA_CATEGORY_IONO = (1 << 4),
    GNSS_AUXILIARY_DATA_CATEGORY_UTC = (1 << 5),
    GNSS_AUXILIARY_DATA_CATEGORY_HEALTH = (1 << 6),
    GNSS_AUXILIARY_DATA_CATEGORY_SVDIR = (1 << 7),
    GNSS_AUXILIARY_DATA_CATEGORY_SVSTEER = (1 << 8),
    GNSS_AUXILIARY_DATA_CATEGORY_SADATA = (1 << 9),
    GNSS_AUXILIARY_DATA_CATEGORY_RTI = (1 << 10),
    GNSS_AUXILIARY_DATA_CATEGORY_CELLDB_INFO = (1 << 11),
    GNSS_AUXILIARY_DATA_CATEGORY_ALL = 0xFFFF,
};

enum class GnssModuleIfaceCategory {
    AGNSS_MODULE_INTERFACE = 1,
    GNSS_GEOFENCING_MODULE_INTERFACE = 2,
    GNSS_NET_INITIATED_MODULE_INTERFACE = 3,
    GNSS_MEASUREMENT_MODULE_INTERFACE = 4,
};

enum class GeofenceEvent {
    GEOFENCE_EVENT_UNCERTAIN = (1 << 0),
    GEOFENCE_EVENT_ENTERED = (1 << 1),
    GEOFENCE_EVENT_EXITED = (1 << 2),
};

enum class GeofenceOperateCategory {
    GEOFENCE_ADD = 1,
    GEOFENCE_DELETE = 2,
};

enum class GeofenceOperateResult {
    GEOFENCE_OPERATION_SUCCESS = 0,
    GEOFENCE_OPERATION_ERROR_UNKNOWN = -1,
    GEOFENCE_OPERATION_ERROR_TOO_MANY_GEOFENCES = -2,
    GEOFENCE_OPERATION_ERROR_GEOFENCE_ID_EXISTS = -3,
    GEOFENCE_OPERATION_ERROR_PARAMS_INVALID = -4,
};

enum class GnssClockValidity {
    GNSS_CLOCK_FLAG_LEAP_SECOND_VALID = (1 << 0),
    GNSS_CLOCK_FLAG_TIME_UNCERTAINTY_VALID = (1 << 1),
    GNSS_CLOCK_FLAG_FULL_BIAS_VALID = (1 << 2),
    GNSS_CLOCK_FLAG_BIAS_VALID = (1 << 3),
    GNSS_CLOCK_FLAG_BIAS_UNCERTAINTY_VALID = (1 << 4),
    GNSS_CLOCK_FLAG_DRIFT_VALID = (1 << 5),
    GNSS_CLOCK_FLAG_DRIFT_UNCERTAINTY_VALID = (1 << 6),
    GNSS_CLOCK_FLAG_CLOCK_JUMP_VALID = (1 << 7),
    GNSS_CLOCK_FLAG_CLOCK_FREQ_BIAS_VALID = (1 << 8),
    GNSS_CLOCK_FLAG_CLOCK_FREQ_DRIFT_VALID = (1 << 9),
};

enum class GnssMeasurementValidity {
    GNSS_MEASUREMENT_SNR_VALID = (1 << 0),
    GNSS_MEASUREMENT_CARRIER_FREQUENCY_VALID = (1 << 1),
    GNSS_MEASUREMENT_CARRIER_CYCLES_VALID = (1 << 2),
    GNSS_MEASUREMENT_CARRIER_PHASE_VALID = (1 << 3),
    GNSS_MEASUREMENT_CARRIER_PHASE_UNCERTAINTY_VALID = (1 << 4),
    GNSS_MEASUREMENT_AUTOMATIC_GAIN_CONTROL_VALID = (1 << 5),
    GNSS_MEASUREMENT_IONO_CORRECT_VALID = (1 << 6),
    GNSS_MEASUREMENT_TROP_CORRECT_VALID = (1 << 7),
    GNSS_MEASUREMENT_SVCLOCK_BIAS_VALID = (1 << 8),
    GNSS_MEASUREMENT_SVCLOCK_DRIFT_VALID = (1 << 9),
};

enum class SatelliteSyncState {
    SATELLITE_SYNC_STATE_UNKNOWN = 0,
    SATELLITE_SYNC_STATE_CODE_LOCK = (1 << 0),
    SATELLITE_SYNC_STATE_BIT_SYNC = (1 << 1),
    SATELLITE_SYNC_STATE_SUBFRAME_SYNC = (1 << 2),
    SATELLITE_SYNC_STATE_TOW_DECODED = (1 << 3),
    SATELLITE_SYNC_STATE_MSEC_AMBIGUOUS = (1 << 4),
    SATELLITE_SYNC_STATE_SYMBOL_SYNC = (1 << 5),
    SATELLITE_SYNC_STATE_GLO_STRING_SYNC = (1 << 6),
    SATELLITE_SYNC_STATE_GLO_TOD_DECODED = (1 << 7),
    SATELLITE_SYNC_STATE_BDS_D2_BIT_SYNC = (1 << 8),
    SATELLITE_SYNC_STATE_BDS_D2_SUBFRAME_SYNC = (1 << 9),
    SATELLITE_SYNC_STATE_GAL_E1BC_CODE_LOCK = (1 << 10),
    SATELLITE_SYNC_STATE_GAL_E1C_2ND_CODE_LOCK = (1 << 11),
    SATELLITE_SYNC_STATE_GAL_E1B_PAGE_SYNC = (1 << 12),
    SATELLITE_SYNC_STATE_SBAS_SYNC = (1 << 13),
    SATELLITE_SYNC_STATE_TOW_KNOWN = (1 << 14),
    SATELLITE_SYNC_STATE_GLO_TOD_KNOWN = (1 << 15),
    SATELLITE_SYNC_STATE_2ND_CODE_LOCK = (1 << 16),
};

enum class GnssMeasurementTrackedCodeCategory {
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_UNKNOWN = 0,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_A = 1,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_B = 2,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_C = 3,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_I = 4,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_L = 5,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_M = 6,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_N = 7,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_P = 8,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_Q = 9,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_S = 10,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_W = 11,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_X = 12,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_Y = 13,
    GNSS_MEASUREMENT_TRACKED_CODE_CATEGORY_Z = 14,
};

enum class GnssAccumulatedDeltaRangeFlag {
    GNSS_ADR_FLAG_UNKNOWN = 0,
    GNSS_ADR_FLAG_VALID = (1 << 0),
    GNSS_ADR_FLAG_RESET = (1 << 1),
    GNSS_ADR_FLAG_CYCLE_SLIP = (1 << 2),
    GNSS_ADR_FLAG_HALF_CYCLE_RESOLVED = (1 << 3),
};

enum class GnssMultipathFlag {
    GNSS_MULTIPATH_FLAG_UNKNOWN = 0,
    GNSS_MULTIPATH_FLAG_PRESENT = 1,
    GNSS_MULTIPATH_FLAG_NOT_PRESENT = 2,
};

enum class GnssNiRequestCategory {
    GNSS_NI_REQUEST_CATEGORY_EMERGENCY_SUPL = 1,
    GNSS_NI_REQUEST_CATEGORY_VOICE = 2,
    GNSS_NI_REQUEST_CATEGORY_UMTS_CONTROL_PLANE = 3,
    GNSS_NI_REQUEST_CATEGORY_UMTS_SUPL = 4,
};

enum class GnssNiResponseCmd {
    GNSS_NI_RESPONSE_CMD_ACCEPT = 1,
    GNSS_NI_RESPONSE_CMD_NO_RESPONSE = 2,
    GNSS_NI_RESPONSE_CMD_REJECT = 3,
};

enum class GnssNiNotificationCategory {
    GNSS_NI_NOTIFICATION_REQUIRE_NOTIFY = (1 << 0),
    GNSS_NI_NOTIFICATION_REQUIRE_VERIFY = (1 << 1),
    GNSS_NI_NOTIFICATION_REQUIRE_PRIVACY_OVERRIDE = (1 << 2),
};

enum class GnssNiRequestEncodingFormat {
    GNSS_NI_ENCODING_FORMAT_NULL = 1,
    GNSS_NI_ENCODING_FORMAT_SUPL_GSM_DEFAULT = 2,
    GNSS_NI_ENCODING_FORMAT_SUPL_UCS2 = 3,
    GNSS_NI_ENCODING_FORMAT_SUPL_UTF8 = 4,
};

enum class ClockHWFreBiasState {
    UNKNOWN = 0,
    NORMAL = 1,
    ABNORMAL = 2,
};

enum class ClockHWFreDriftState {
    UNKNOWN = 0,
    NORMAL = 1,
    ABNORMAL = 2,
};

/*
 * Definition of Cell ID structure.
 */
typedef struct {
    size_t size;

    /* See CellIdCategory for the definition of category. */
    uint16_t category;

    /* Mobile Country Code. */
    uint16_t mcc;

    /* Mobile Network Code. */
    uint16_t mnc;

    /* Location Area Code. */
    uint16_t lac;

    /* 2G:Cell id. 3G:Utran Cell id. LTE:Cell Global Id EUTRA. */
    uint32_t cid;

    /* Tracking Area Code. */
    uint16_t tac;

    /* Physical Cell id. */
    uint16_t pcid;

    /* NR cell id */
    uint64_t nci;
} CellId;

/*
 * WiFi MAC information.
 */
typedef struct {
    size_t size;
    uint8_t mac[6];
} MacInfo;

/*
 * AGNSS reference information.
 */
typedef struct {
    size_t size;

    /* See AgnssRefInfoCategory for the definition of category. */
    uint32_t category;

    union {
        CellId cellId;
        MacInfo mac;
    } u;
} AgnssReferenceInfo;

/*
 * Data service network state.
 */
typedef struct {
    size_t size;

    uint32_t netId;

    /* See ApnIpCategory for the definition of state. */
    uint32_t apnIpCategory;

    char apn[APN_LENGTH_MAXIMUM];

    /* See DataConnectionState for the definition of state. */
    uint8_t state;
} NetworkState;

/*
 * GNSS location structure.
 */
typedef struct {
    size_t size;

    /* See GnssLocationValidity for the definition of fieldValidity. */
    uint32_t fieldValidity;

    double latitude;

    double longitude;

    /* Altitude in meters. */
    double altitude;

    /* Speed in meters per second. */
    float speed;

    /* Heading in degrees. */
    float bearing;

    /* Horizontal position accuracy in meters. */
    float horizontalAccuracy;

    /* Vertical position accuracy in meters. */
    float verticalAccuracy;

    /* Speed accuracy in meter per seconds. */
    float speedAccuracy;

    /* Bearing accuracy in degrees. */
    float bearingAccuracy;

    /* Timestamp for the location fix. Number of milliseconds since January 1, 1970. */
    int64_t timeForFix;

    /* Time since the system was booted, and include deep sleep. The unit is nanosecond. */
    uint64_t timeSinceBoot;

    /* Time uncertainty in nanosecond. */
    uint64_t timeUncertainty;
} GnssLocation;

/*
 * Configuration of the GNSS caching function.
 */
typedef struct {
    size_t size;

    /* Minimus interval between locations in millisecond. */
    uint32_t interval;

    /*
     * If the value is true, the cached locations
     * are reported and the AP is woken up after the FIFO is full.
     */
    bool fifoFullNotify;
} GnssCachingConfig;

/*
 * Status information of a single satellite.
 */
typedef struct {
    size_t size;

    /* Satellite ID number for the satellite. */
    int16_t satelliteId;

    /*
     * Defines the constellation category.
     * See ConstellationCategory for the definition of constellationCategory.
     */
    uint8_t constellationCategory;

    /* Carrier-to-noise density in dB-Hz. */
    float cn0;

    /* Elevation of satellite in degrees. */
    float elevation;

    /* Azimuth of satellite in degrees. */
    float azimuth;

    /* Carrier frequency of the signal tracked. The unit is Hz. */
    float carrierFrequency;

    /* See SatelliteAdditionalInfo for the definition of satelliteAdditionalInfo. */
    uint32_t satelliteAdditionalInfo;
} SatelliteStatusInfo;

/*
 * Status informations of all satellites.
 */
typedef struct {
    size_t size;

    /* Number of all satellites that can be viewed. */
    uint32_t satellitesNum;

    /* Array of all satellites information. */
    SatelliteStatusInfo satellitesList[SATELLITE_NUM_MAXIMUM];
} GnssSatelliteStatus;

/*
 * Callback for location reporting.
 */
typedef void (*OnLocationChange)(GnssLocation* location);

/*
 * Callback for GNSS working status reporting.
 * Parameters:
 *    status  - Working status of GNSS chip.
 *              See GnssWorkingStatus for the definition of status.
 */
typedef void (*OnGnssWorkingStatusChange)(uint16_t* status);

/*
 * Callback for satellite status reporting.
 */
typedef void (*OnSatelliteStatusChange)(GnssSatelliteStatus* status);

/*
 * Callback for NMEA info reporting.
 * Parameters:
 *    time   - Timestamp when the nmea was reported. Milliseconds since January 1, 1970.
 *    nmea  - NMEA string.
 *    length  - Length of NMEA string.
 */
typedef void (*OnGnssNmeaChange)(int64_t time, const char* nmea, int length);

/*
 * Callback for GNSS capabilities reporting.
 * Parameters:
 *    capabilities   - GNSS capabilities. See GnssCapabilities for the definition of capabilities.
 */
typedef void (*OnCapabilitiesChange)(uint32_t capabilities);

/*
 * Request to delivery GNSS reference information.
 * Parameters:
 *    category   - Category of GNSS reference information, See GnssRefInfoCategory for the definition of category.
 */
typedef void (*RequestGnssReferenceInfo)(int category);

/*
 * GNSS basic config structure.
 */
typedef struct {
    size_t size;

    /* Minimus interval between locations in ms */
    uint32_t minInterval;

    /* See GnssWorkingMode for the definition of gnssMode */
    int gnssMode;
} GnssBasicConfigPara;

/*
 * GNSS config structure.
 */
typedef struct {
    size_t size;

    /*
     * Indicates the method of location reporting,
     * whether to report immediately or after caching for a
     * period of time. See GnssStartCategory for the definition of startCategory.
     */
    uint32_t startCategory;

    union {
        GnssBasicConfigPara gnssBasicConfig;
        GnssCachingConfig gnssCacheConfig;
    } u;
} GnssConfigParameter;

/*
 * GNSS reference time.
 */
typedef struct {
    size_t size;

    /* UTC time received from the NTP server, Milliseconds since January 1, 1970. */
    int64_t time;

    /* Time since the system was booted, and include deep sleep. The unit is milliseconds. */
    int64_t elapsedRealtime;

    /* This is uncertainty of time. The unit is milliseconds. */
    int uncertaintyOfTime;
} GnssRefTime;

/*
 * GNSS reference information structure.
 */
typedef struct {
    size_t size;

    /*
     * Category of GNSS reference information,
     * See GnssRefInfoCategory for the definition of category.
     */
    int category;

    union {
        GnssRefTime time;
        GnssLocation gnssLocation;
        GnssLocation bestLocation;
    } u;
} GnssReferenceInfo;

/*
 * Request the client to download extended ephemeris data.
 */
typedef void (*RequestExtendedEphemeris)(void);

/*
 * Callback for GNSS cache location information reporting.
 */
typedef void (*OnCachedLocationsChange)(const GnssLocation** locationArray, size_t arrayLength);

/*
 * GNSS basic callback functions.
 */
typedef struct {
    size_t size;
    OnLocationChange locationUpdate;
    OnGnssWorkingStatusChange gnssWorkingStatusUpdate;
    OnSatelliteStatusChange satelliteStatusUpdate;
    OnGnssNmeaChange nmeaUpdate;
    OnCapabilitiesChange capabilitiesUpdate;
    RequestGnssReferenceInfo requestRefInfo;
    RequestExtendedEphemeris requestExtendedEphemeris;
} GnssBasicCallbackIfaces;

/*
 * GNSS cached location callback functions.
 */
typedef struct {
    size_t size;
    OnCachedLocationsChange cachedLocationUpdate;
} GnssCacheCallbackIfaces;

/*
 * GNSS callback structure.
 */
typedef struct {
    size_t size;
    GnssBasicCallbackIfaces gnssCallback;
    GnssCacheCallbackIfaces gnssCacheCallback;
} GnssCallbackStruct;

/*
 * GNSS vendor interface definition.
 */
typedef struct {
    size_t size;

    /* Enable the GNSS function. Initializing the GNSS Chip. */
    int (*enableGnss)(GnssCallbackStruct* callbacks);

    /* Disables the GNSS function. */
    int (*disableGnss)(void);

    /* Start navigating. See GnssStartCategory for the definition of category. */
    int (*startGnss)(uint32_t category);

    /* Stops navigating. See GnssStartCategory for the definition of category. */
    int (*stopGnss)(uint32_t category);

    /* Inject reference information into the GNSS chip.
     * See GnssRefInfoCategory for the definition of category. */
    int (*injectsGnssReferenceInfo)(int category, GnssReferenceInfo* info);

    /* Set GNSS configuration parameters. */
    int (*setGnssConfigPara)(GnssConfigParameter* para);

    /*
     * This function is used to delete the assistance data,
     * which will not be used in the next GNSS positioning.
     * See GnssAuxiliaryDataCategory for the definition of flags.
     */
    void (*removeAuxiliaryData)(uint16_t flags);

    /* Injects extended ephemeris data into the GNSS. */
    int (*injectExtendedEphemeris)(char* data, int length);

    /* Return the cached locations size. */
    int (*getCachedLocationsSize)();

    /* Retrieve all cached locations currently stored and clear the buffer. */
    void (*flushCachedGnssLocations)();

    /* Get a pointer to GNSS module interface. See GnssModuleIfaceCategory for the definition of iface. */
    const void* (*getGnssModuleIface)(int iface);
} GnssVendorInterface;

/*
 * GNSS vendor device definition.
 */
struct GnssVendorDevice {
    size_t size;
    const GnssVendorInterface* (*getGnssInterface)();
};

/*
 * Defines the structure of the request for operating the AGNSS data link.
 */
typedef struct {
    size_t size;

    /* See AgnssCategory for the definition of agnssCategory */
    uint16_t agnssCategory;

    /* See AgnssDataConnectionSetUpCategory for the definition of requestCategory. */
    uint16_t requestCategory;

    /* IPv4 address. */
    uint32_t ipaddr;

    /* IPv6 address. */
    struct sockaddr_storage sockAddr;
} AgnssDataConnectionRequest;

/*
 * Request to setup the AGNSS data link.
 */
typedef void (*RequestSetupAgnssDataConnection)(const AgnssDataConnectionRequest* request);

/*
 * Callback function for requesting setid.
 * Parameters:
 *    category   - Category of setid, See enum class AgnssSetidCategory for the definition of setidCategory.
 */
typedef void (*RequestDeliverySetid)(uint16_t setidCategory);

/*
 * Callback function for requesting AGNSS reference information.
 * Parameters:
 *    category   - Category of AGNSS reference information,
 *                 See enum class AgnssRefInfoCategory for the definition of category.
 */
typedef void (*RequestDeliveryReferenceInfo)(uint32_t category);

/*
 * Definition of the AGNSS callback interfaces.
 */
typedef struct {
    size_t size;
    RequestSetupAgnssDataConnection requestSetupDataLink;
    RequestDeliverySetid requestSetid;
    RequestDeliveryReferenceInfo requestRefInfo;
} AgnssCallbackIfaces;

/*
 * Interface for AGNSS functions.
 */
typedef struct {
    size_t size;

    /* Set AGNSS callback interfaces. */
    bool (*setAgnssCallback)(AgnssCallbackIfaces* callbacks);

    /* Sets the AGNSS reference information. */
    bool (*setAgnssReferenceInfo)(const AgnssReferenceInfo* refInfo);

    /*
     * Set the set ID.
     * Parameters:
     *    category  - Category of setid, See enum class AgnssSetidCategory for the definition of category.
     *    setid     - Setid string.
     *    length    - Length of setid string.
     */
    bool (*setSetid)(uint16_t category, const char* setid, size_t length);

    /*
     * Set the AGNSS Server Information.
     * Parameters:
     *    category - Category of AGNSS. See AgnssCategory for the definition of category.
     *    server   - AGNSS server information.
     *    length   - Length of server string.
     *    port     - Port of AGNSS server.
     */
    bool (*setAgnssServer)(uint16_t category, const char* server, size_t length, int32_t port);

    /* Used to receive network state changes. */
    void (*onNetworkStateChange)(const NetworkState* state);
} AgnssModuleInterface;

/*
 * Callback for geofence event reporting.
 * Parameters:
 *    geofenceId - The id of geofence.
 *    location   - The current GNSS location.
 *    event      - Current geofencing event. See GeofenceEvent for the definition of event.
 *    timestamp  - Timestamp when the transition was detected. Milliseconds since January 1, 1970.
 */
typedef void (*OnGeofenceEventChange)(int32_t geofenceId,  GnssLocation* location,
    int32_t event, int64_t timestamp);

/*
 * Callback function that indicates whether the geofence service is available.
 *
 * Parameters:
 *    isAvailable is true when GNSS geofence service is available.
 */
typedef void (*OnGeofenceAvailabilityChange)(bool isAvailable);

/*
 * Callback function indicating the result of the geofence operation.
 *
 *    geofenceId      - Id of the geofence.
 *    operateCategory - Geofence operate category.
                          See GeofenceOperateCategory for the definition of operateCategory.
 *    result          - Operation result. See GeofenceOperateResult for the definition of result.
 */
typedef void (*OnGeofenceOperateResultChange)(int32_t geofenceId, int32_t operateCategory,
    int32_t result);

/*
 * Callbacks for geofence informations reporting.
 */
typedef struct {
    size_t size;
    OnGeofenceAvailabilityChange geofenceAvailabilityUpdate;
    OnGeofenceEventChange geofenceEventUpdate;
    OnGeofenceOperateResultChange geofenceOperateResultUpdate;
} GeofenceCallbackIfaces;

/*
 * Interface for GNSS Geofence.
 */
typedef struct {
    size_t size;

    /*
     * Set the geofence callback interfaces.
     */
    bool (*setCallback)(GeofenceCallbackIfaces* callbacks);

    /*
     * Add a GNSS geofence.
     * Parameters:
     *    geofenceId           - The id of the geofence.
     *    latitude, longtitude - Center of a circular geofence.
     *    radius               - Radius of a circular geofence.
     *    monitorEvent         - Which geofence event to monitor.
     *                           See GeofenceEvent for the definition of monitorEvent.
     */
    bool (*addGnssGeofence)(int32_t geofenceId, double latitude, double longitude,
       double radius, int32_t monitorEvent);

    /*
     * Delete a GNSS geofence.
     *    geofenceId - The id of the geofence.
     */
    bool (*deleteGnssGeofence)(int32_t geofenceId);
} GeofenceModuleInterface;

/*
 * Definition of the GNSS clock information structure.
 */
typedef struct {
    size_t size;

    /*
     * Identifies which field is valid.
     * See GnssClockValidity for the definition of fieldValidFlags.
     */
    uint16_t fieldValidFlags;

    /*
     * Leap second data.
     */
    int16_t leapSecond;

    /*
     * Indicates the clock time of the GNSS receiver, the unit is nanosecond.
     * This is a mandatory value.
     */
    int64_t receiverClockTime;

    /*
     * Uncertainty of the receiverClockTime, the unit is nanosecond.
     */
    double timeUncertainty;

    /*
     * The difference between receiverClockTime and the true GPS time since 0000Z, January 6, 1980.
     * the unit is nanosecond.
     */
    int64_t rcvClockFullBias;

    /*
     * Sub-nanosecond bias of receiverClockTime.
     */
    double rcvClockSubBias;

    /*
     * Uncertainty of the local estimate of GPS time (clock bias 'rcvClockFullBias' and 'rcvClockSubBias' feild)
     * in nanoseconds.
     */
    double biasUncertainty;

    /*
     * The clock's drift of receiver clock. the unit is nanosecond (per second).
     */
    double clockDrift;

    /*
     * The uncertainty of clockDrift. the unit is nanosecond (per second).
     */
    double clockDriftUncertainty;

    /*
     * Indicates hardware clock discontinuity count.
     * This is a mandatory value.
     */
    uint32_t clockInterruptCnt;

    /*
     * Indicates clockJump threshold of hardware clock. the unit is nanosecond.
     * the clock bias ('rcvClockFullBias' + 'rcvClockSubBias' should be less than clockJumpThreshold)
     */
    double clockJumpThreshold;

    /*
     * Indicates clockHWFreBias event, If the crystal oscillator(XO) has a frequency offset exception event,
     * this enumeration field reports the state.
     * If this field is frequently reported, check the environment or hardware status of the XO.
     * See ClockHWFreBiasState for the definition of clockHWFreBiasIndicator.
     */
    uint32_t clockHWFreBiasIndicator;

    /*
     * Indicates clockHWFreDrift event, If the crystal oscillator(XO) has a frequency drift exception event,
     * this enumeration field reports the state.
     * If this field is frequently reported, check the environment or hardware status of the XO.
     * See clockHWFreDriftState for the definition of clockHWFreDriftIndicator.
     */
    uint32_t clockHWFreDriftIndicator;
} GnssClockInfo;

/*
 * Definition of the GNSS measurement information.
 */
typedef struct {
    size_t size;

    /*
     * Identifies which field is valid.
     * See GnssMeasurementValidity for the definition of fieldValidFlags.
     */
    uint32_t fieldValidflags;

    /*
     * Satellite ID number.
     * This is a mandatory value.
     */
    int16_t satelliteId;

    /*
     * Defines the constellation category.
     * See ConstellationCategory for the definition of constellationCategory.
     */
    int16_t constellationCategory;

    /*
     * Measurement generation time offset in nanoseconds.
     * This is a mandatory value.
     * The formula for calculating the measurement time is as follows:
     *     measurement time = GnssClockInfo::receiverClockTime + timeOffset
     */
    double timeOffset;

    /*
     * Satellite sync state. See SatelliteSyncState for the definition of syncState.
     * This is a mandatory value.
     */
    uint32_t syncState;

    /*
     * The received satellite Time-of-Week in nanoseconds.
     */
    int64_t receivedSatelliteTime;

    /*
     * Uncertainty of the received satellite Time-of-Week in nanoseconds.
     */
    int64_t receivedSatelliteTimeUncertainty;

    /*
     * Carrier-to-noise density. The unit is dB-Hz.
     * This is a mandatory value.
     */
    double cn0;

    /*
     * Pseudorange rate. The unit is m/s.
     */
    double pseudorangeRate;

    /*
     * Uncertainty of the pseudorangeRate. The unit is m/s.
     * This is a mandatory value.
     */
    double pseudorangeRateUncertainty;

    /*
     * Accumulated delta range's state.
     * See GnssAccumulatedDeltaRangeFlag for the definition.
     * This is a mandatory value.
     */
    uint32_t accumulatedDeltaRangeFlag;

    /*
     * Accumulated delta range since the last channel reset. The unit is meters.
     */
    double accumulatedDeltaRange;

    /*
     * Uncertainty of the accumulated delta range. The unit is meters.
     */
    double accumulatedDeltaRangeUncertainty;

    /*
     * Carrier frequency at which codes and messages are modulated. The unit is Hz.
     */
    float carrierFrequency;

    /*
     * The count of carrier cycles between satellite and receiver.
     */
    int64_t carrierCyclesCount;

    /*
     * Carrier phase, in the range [0.0, 1.0].
     */
    double carrierPhase;

    /*
     * Uncertainty of the carrierPhase.
     */
    double carrierPhaseUncertainty;

    /*
     * Indicates the 'multipath' flag.
     * See GnssMultipathFlag for the definition of multipathFlag.
     */
    uint32_t multipathFlag;

    /*
     * Automatic gain control (AGC) level in dB.
     */
    double agcGain;

    /*
     * The category of code that is currently being tracked in the GNSS measurement.
     * See GnssMeasurementTrackedCodeCategory for the definition of codeCategory.
     */
    uint32_t codeCategory;

    /*
     * Iono-correct value in meters.
     */
    double ionoCorrect;

    /*
     * Trop-correct value in meters.
     */
    double tropCorrect;

    /*
     * Satellite clock bias value in meters.
     */
    double satelliteClockBias;

    /*
     * Satellite clock drift bias value in meters.
     */
    double satelliteClockDriftBias;
} GnssMeasurement;

/*
 * Definition of the GNSS measurement informations.
 */
typedef struct {
    size_t size;

    GnssClockInfo gnssClock;

    /* Time since the system was booted, and include deep sleep. The unit is nanoseconds. */
    uint64_t elapsedRealtime;

    /* This is uncertainty of elapsedRealtime. The unit is nanoseconds. */
    uint64_t uncertainty;

    /* Number of measurements. */
    size_t measurementCount;

    /* The array of measurements. */
    GnssMeasurement measurements[SATELLITE_NUM_MAXIMUM];
} GnssMeasurementInfo;

/*
 * Callback for reporting the GNSS measurement informations.
 */
typedef void (*OnGnssMeasurementChange)(GnssMeasurementInfo* data);

/*
 * Definition of the GNSS measurement callback interface.
 */
typedef struct {
    size_t size;
    OnGnssMeasurementChange gnssMeasurementUpdate;
} GnssMeasurementCallbackIfaces;

/*
 * Definition of the GNSS measurement interface.
 */
typedef struct {
    size_t size;

    /*
     * Enable measurement information reporting and register callback.
     */
    bool (*enable)(GnssMeasurementCallbackIfaces* callbacks);

    /*
     * Disable measurement information reporting and unregister callback.
     */
    void (*disable)();
} GnssMeasurementInterface;

/*
 * Definition of the GNSS NI notification request structure.
 */
typedef struct {
    size_t size;

    /*
     * An ID of GNSS NI notifications.
     */
    int16_t gnssNiNotificationId;

    /*
     * Category of GNSS NI Request. See GnssNiRequestCategory for the definition of gnssNiRequestCategory.
     */
    int16_t gnssNiRequestCategory;

    /*
     * Category of notification. See GnssNiNotificationCategory for the definition of gnssNiCategory.
     */
    int32_t notificationCategory;

    /*
     * Timeout to wait for user response. The unit is seconds.
     */
    int32_t requestTimeout;

    /*
     * Default response command when timeout.
     */
    int32_t defaultResponseCmd;

    /*
     * Supplicant information.
     */
    char supplicantInfo[GNSS_NI_SUPPLICANT_INFO_LENGTH_MAXIMUM];

    /*
     * Notification message text.
     */
    char notificationText[GNSS_NI_NOTIFICATION_TEXT_LENGTH_MAXIMUM];

    /*
     * See GnssNiRequestEncodingFormat for the definition of supplicantInfoEncoding.
     */
    int16_t supplicantInfoEncoding;

    /*
     * See GnssNiRequestEncodingFormat for the definition of notificationTextEncoding.
     */
    int16_t notificationTextEncoding;
} GnssNiNotificationRequest;

/*
 * Callback for GNSS NI notification reporting.
 */
typedef void (*OnGnssNiNotificationChange)(GnssNiNotificationRequest *notification);

/*
 * Definition of GNSS NI callback structure.
 */
typedef struct {
    OnGnssNiNotificationChange reportNiNotification;
} GnssNetInitiatedCallbacks;

/*
 * Definition of GNSS NI interface.
 */
typedef struct {
    size_t size;

    /* Set callbacks. */
    void (*setCallback)(GnssNetInitiatedCallbacks *callbacks);

    /*
     * Sends user response command.
     * Parameters:
     *    gnssNiNotificationId - The id of GNSS NI notifications.
     *    userResponse         - User reponse command.
     *                           See GnssNiResponseCmd for the definition of userResponse.
     */
    void (*sendUserResponse)(int32_t gnssNiNotificationId, int32_t userResponse);

    /*
     * Send network initiated message.
     */
    void (*sendNetworkInitiatedMsg)(uint8_t *msg, size_t length);
} GnssNetInitiatedInterface;
} // namespace Location
} // namespace HDI
} // namespace OHOS

#endif /* OHOS_HDI_LOCATION_LOCATION_VENDOR_LIB_H */
