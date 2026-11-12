import datetime
import re

from esphome import automation
import esphome.codegen as cg
from esphome.components import binary_sensor, sensor, switch, text_sensor
from esphome.components.esp32 import (
    CONF_PARTITIONS,
    # add_extra_build_file,
    add_idf_component,
    add_idf_sdkconfig_option,
    only_on_variant,
)
from esphome.components.esp32.const import VARIANT_ESP32C6, VARIANT_ESP32H2
import esphome.config_validation as cv
from esphome.const import (
    CONF_AP,
    CONF_AREA,
    CONF_CHANNEL,
    CONF_COMPONENTS,
    CONF_DATE,
    CONF_DEBUG,
    CONF_DEVICE,
    CONF_ID,
    CONF_LAMBDA,
    CONF_MAX_LENGTH,
    CONF_NAME,
    CONF_ON_VALUE,
    CONF_POWER_SUPPLY,
    CONF_TRIGGER_ID,
    CONF_TYPE,
    CONF_VALUE,
    CONF_VERSION,
    CONF_WIFI,
)
from esphome.core import CORE, EsphomeError
import esphome.final_validate as fv

from .const import (
    CONF_HUE_EMULATION,
    CONF_HUE_ENDPOINT,
    CONF_ACCESS,
    CONF_AS_GENERIC,
    CONF_ATTRIBUTE_ID,
    CONF_ATTRIBUTES,
    CONF_CLUSTERS,
    CONF_DEVICE_TYPE,
    CONF_ENDPOINTS,
    CONF_IDENT_TIME,
    CONF_MAC,
    CONF_MANUAL_START,
    CONF_MANUFACTURER,
    CONF_NUM,
    CONF_ON_JOIN,
    CONF_ON_RECALL_SCENE,
    CONF_REPORT,
    CONF_ROLE,
    CONF_ROUTER,
    CONF_SCALE,
    CONF_TRUST_CENTER_KEY,
    CONF_JOIN_MODE,
    CONF_LOG_NETWORK_KEY,
    CONF_MANUFACTURER_CODE,
    CONF_ZCL_VERSION,
    CONF_STACK_VERSION,
    CONF_HW_VERSION,
    CONF_SW_BUILD_ID,
)
from .types import (
    ReportAction,
    ReportAttrAction,
    ResetZigbeeAction,
    SetAttrAction,
    StartZigbeeAction,
    ZigBeeAttribute,
    ZigBeeComponent,
    ZigBeeJoinTrigger,
    ZigBeeRecallSceneTrigger,
    ZigBeeOnValueTrigger,
)
from .zigbee_const import ATTR_ACCESS, ATTR_TYPE, CLUSTER_ID, CLUSTER_ROLE, DEVICE_ID
from .zigbee_ep import create_ep

DEPENDENCIES = ["esp32"]

comp_ids = 0


def get_c_size(bits, options):
    return str([n for n in options if n >= int(bits)][0])


def get_c_type(attr_type):
    if attr_type == "BOOL":
        return cg.bool_
    if attr_type == "SINGLE":
        return cg.float_
    if attr_type == "DOUBLE":
        return cg.double
    if "STRING" in attr_type:
        return cg.std_string
    test = re.match(r"(^U?)(\d{1,2})(BITMAP$|BIT$|BIT_ENUM$|$)", attr_type)
    if test and test.group(2):
        return getattr(cg, "uint" + get_c_size(test.group(2), [8, 16, 32, 64]))
    test = re.match(r"^S(\d{1,2})$", attr_type)
    if test and test.group(1):
        return getattr(cg, "int" + get_c_size(test.group(1), [16, 32, 64]))
    raise EsphomeError(f"Zigbee: type {attr_type} not supported or implemented")


def get_cv_by_type(attr_type):
    if attr_type == "BOOL":
        return cv.boolean
    if attr_type in ["SEMI", "SINGLE", "DOUBLE"]:
        return cv.float_
    if "STRING" in attr_type:
        return cv.string
    test = re.match(r"(^U?)(\d{1,2})(BITMAP$|BIT$|BIT_ENUM$|$)", attr_type)
    if test and test.group(2):
        return cv.positive_int
    test = re.match(r"^S(\d{1,2})$", attr_type)
    if test and test.group(1):
        return cv.int_
    raise cv.Invalid(f"Zigbee: type {attr_type} not supported or implemented")


def get_default_by_type(attr_type):
    if "CHAR_STRING" == attr_type:
        return ""
    return 0


def validate_eui64(value):
    """Validate a Zigbee IEEE EUI-64 address.

    Accepts 8 hex octets separated by ':' or '-' (MSB-first, the order the
    device logs its 'Own IEEE EUI-64'), e.g. '84:2E:14:FF:FE:01:02:03'.
    Returns a list of 8 ints in MSB-first order.
    """
    value = cv.string_strict(value)
    parts = re.split(r"[:-]", value.strip())
    if len(parts) != 8:
        raise cv.Invalid(
            f"MAC/EUI-64 must have 8 octets separated by ':' or '-', got {len(parts)}"
        )
    octets = []
    for part in parts:
        if not re.fullmatch(r"[0-9A-Fa-f]{1,2}", part):
            raise cv.Invalid(f"Invalid hex octet '{part}' in MAC/EUI-64")
        octets.append(int(part, 16))
    return octets


def validate_link_key(value):
    """Validate a 128-bit Zigbee trust center link key (16 bytes).

    Accepts the 16 bytes as hex in several styles:
      - contiguous: '00112233445566778899AABBCCDDEEFF'
      - separated:  '00:11:...:FF' / '00 11 ... FF' / '00,11,...,FF'
      - C-array:    '0x00, 0x11, ... 0xFF'
    Returns a list of 16 ints in the order written (network/big-endian order).
    """
    value = cv.string_strict(value)
    cleaned = value.strip().lower().replace("0x", "")
    parts = [p for p in re.split(r"[\s:,;-]+", cleaned) if p]
    # Allow one contiguous 32-char hex token.
    if len(parts) == 1 and len(parts[0]) == 32:
        token = parts[0]
        parts = [token[i : i + 2] for i in range(0, 32, 2)]
    if len(parts) != 16:
        raise cv.Invalid(
            f"Trust center link key must be 16 bytes (128-bit), got {len(parts)}"
        )
    octets = []
    for part in parts:
        if not re.fullmatch(r"[0-9a-f]{1,2}", part):
            raise cv.Invalid(f"Invalid hex byte '{part}' in trust center link key")
        octets.append(int(part, 16))
    return octets


def validate_clusters(config):
    for attr in config.get(CONF_ATTRIBUTES):
        if isinstance(config.get(CONF_ID), int) and config.get(CONF_ID) >= 0xFC00:
            if not {CONF_TYPE, CONF_ACCESS, CONF_VALUE} <= attr.keys():
                raise cv.Invalid(
                    f"Parameters {CONF_TYPE}, {CONF_VALUE} and {CONF_ACCESS} are need for custom cluster."
                )
    return config


def validate_string_attributes(config):
    if "CHAR_STRING" == config[CONF_TYPE]:
        if CONF_MAX_LENGTH not in config.keys():
            raise cv.Invalid(
                f"The '{CONF_MAX_LENGTH}' parameter is mandatory for string attributes."
            )

        # Check that size of default value matches CONF_MAX_LENGTH
        if len(config[CONF_VALUE]) > config[CONF_MAX_LENGTH]:
            raise cv.Invalid(
                "The default value is larger than the maximum length of the string attribute."
            )
    return config


def validate_attributes(config):
    if CONF_VALUE in config:
        config[CONF_VALUE] = get_cv_by_type(config[CONF_TYPE])(config[CONF_VALUE])
    else:
        config[CONF_VALUE] = get_default_by_type(config[CONF_TYPE])
    config[CONF_ACCESS] = (
        ATTR_ACCESS[config[CONF_ACCESS]] + config[CONF_REPORT] * 4
        if CONF_ACCESS in config
        else 0
    )
    validate_string_attributes(config)

    return config


def final_validate(config):
    esp_conf = fv.full_config.get()["esp32"]
    if CONF_PARTITIONS in esp_conf:
        with open(
            CORE.relative_config_path(esp_conf[CONF_PARTITIONS]), encoding="utf8"
        ) as f:
            partitions = f.read()
            if ("zb_storage" not in partitions) and ("zb_fct" not in partitions):
                raise cv.Invalid(
                    "Add \n'zb_storage, data, fat,   , 16K,'\n'zb_fct, data, fat, , 1K,'\n to your custom partition table."
                )
    else:
        raise cv.Invalid(
            f"Use '{CONF_PARTITIONS}' in esp32 to specify a custom partition table including zigbee partitions"
        )
    if CONF_WIFI in fv.full_config.get():
        if CONF_AP in fv.full_config.get()[CONF_WIFI]:
            raise cv.Invalid("Zigbee can't be used together with an Wifi Access Point.")
    global comp_ids  # noqa: PLW0603
    comp_ids = len(CORE.component_ids)
    return config


FINAL_VALIDATE_SCHEMA = cv.Schema(final_validate)


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(ZigBeeComponent),
            cv.Optional(CONF_NAME): cv.string,
            cv.Optional(CONF_MAC): validate_eui64,
            cv.Optional(CONF_TRUST_CENTER_KEY): validate_link_key,
            # distributed: la trust_center_key s'instal.la com a clau DISTRIBUIDA (dTCLK) i s'habilita el join a
            # xarxes distribuides (Philips Hue Bridge, ZLL). centralized: clau preconfigurada de TC centralitzat
            # (coordinadors Zigbee 3.0: ZHA, Z2M, deCONZ amb clau no estandard).
            cv.Optional(CONF_JOIN_MODE, default="distributed"): cv.one_of("distributed", "centralized", lower=True),
            # log_network_key: true -> en unir-se (o en rearrancar ja unit) escriu la clau de xarxa al log, per
            # carregar-la al sniffer zigbeelogger i desxifrar el transit. NOMES per depurar: la clau obre la xarxa.
            cv.Optional(CONF_LOG_NETWORK_KEY, default=False): cv.boolean,
            # Canal(es) Zigbee a usar (11-26). Un entero o una lista. Si se omite,
            # se escanean todos los canales (mas lento y peor con redes solapadas).
            cv.Optional(CONF_CHANNEL): cv.Any(
                cv.int_range(min=11, max=26),
                cv.ensure_list(cv.int_range(min=11, max=26)),
            ),
            cv.Optional(CONF_MANUFACTURER, default="esphome"): cv.string,
            # Manufacturer code del NODE DESCRIPTOR (0x100B = Philips/Signify). Sense aixo l'esp posa el seu.
            cv.Optional(CONF_MANUFACTURER_CODE): cv.hex_uint16_t,
            # Atributs del cluster Basic que l'ESP deixava per defecte (ZCLVersion, StackVersion, HWVersion,
            # SWBuildID 0x4000).
            cv.Optional(CONF_ZCL_VERSION): cv.uint8_t,
            cv.Optional(CONF_STACK_VERSION, default=0): cv.uint8_t,
            cv.Optional(CONF_HW_VERSION, default=0): cv.uint8_t,
            cv.Optional(CONF_SW_BUILD_ID): cv.All(cv.string, cv.Length(max=16)),
            cv.Optional(
                CONF_DATE, default=datetime.datetime.now().strftime("%Y%m%d")
            ): cv.string,
            cv.Optional(CONF_IDENT_TIME): cv.int_,
            cv.Optional(CONF_POWER_SUPPLY, default=0): cv.int_,  # make enum
            cv.Optional(CONF_VERSION, default=0): cv.int_,
            cv.Optional(CONF_AREA, default=0): cv.int_,  # make enum
            cv.Optional(CONF_ROUTER, default=False): cv.boolean,
            cv.Optional(CONF_DEBUG, default=False): cv.boolean,
            # manual_start: true -> la pila Zigbee no arranca en el boot; hay que
            # lanzarla con la accion 'zigbee.start' (patron: ventana WiFi para OTA
            # durante N segundos y despues wifi.disable + zigbee.start).
            cv.Optional(CONF_MANUAL_START, default=False): cv.boolean,
            # Emulacio Hue (vegeu hue_emu.h): descriptor ZLL 0xC05E/0x0210, clusters 0xFC01/0xFC03/0xFC04/0x1000,
            # atributs de fabricant 0x100B i comandes Hue (estat 0xFC03 cmd 0x00, guardar escena Scenes manuf cmd 0x02).
            cv.Optional(CONF_HUE_EMULATION, default=False): cv.boolean,
            cv.Optional(CONF_HUE_ENDPOINT, default=11): cv.int_range(1, 240),
            cv.Optional(CONF_COMPONENTS): cv.Any(
                cv.one_of("all", "none", lower=True),
                cv.ensure_list(cv.use_id(cg.EntityBase)),
            ),
            cv.Optional(CONF_AS_GENERIC, default=False): cv.boolean,
            cv.Optional(CONF_ENDPOINTS): cv.ensure_list(
                cv.Schema(
                    {
                        cv.Required(CONF_DEVICE_TYPE): cv.enum(DEVICE_ID, upper=True),
                        cv.Optional(CONF_NUM): cv.int_range(1, 240),
                        cv.Optional(CONF_CLUSTERS): cv.ensure_list(
                            cv.Schema(
                                {
                                    cv.Required(CONF_ID): cv.Any(
                                        cv.enum(CLUSTER_ID, upper=True),
                                        cv.int_range(0xFC00, 0xFFFF),
                                    ),
                                    cv.Optional(CONF_ROLE, default="Server"): cv.enum(
                                        CLUSTER_ROLE, upper=True
                                    ),
                                    cv.Optional(CONF_ATTRIBUTES): cv.ensure_list(
                                        cv.Schema(
                                            {
                                                cv.GenerateID(): cv.declare_id(
                                                    ZigBeeAttribute
                                                ),
                                                cv.Required(CONF_ATTRIBUTE_ID): cv.int_,
                                                cv.Required(CONF_TYPE): cv.enum(
                                                    ATTR_TYPE, upper=True
                                                ),
                                                cv.Optional(CONF_ACCESS): cv.enum(
                                                    ATTR_ACCESS, upper=True
                                                ),
                                                cv.Optional(CONF_VALUE): cv.valid,
                                                cv.Optional(
                                                    CONF_REPORT, default=False
                                                ): cv.Any(
                                                    cv.boolean,
                                                    cv.one_of("force", lower=True),
                                                ),
                                                cv.Optional(
                                                    CONF_ON_VALUE
                                                ): automation.validate_automation(
                                                    {
                                                        cv.GenerateID(
                                                            CONF_TRIGGER_ID
                                                        ): cv.declare_id(
                                                            ZigBeeOnValueTrigger
                                                        ),
                                                    }
                                                ),
                                                cv.Optional(CONF_DEVICE): cv.use_id(
                                                    cg.EntityBase
                                                ),
                                                cv.Optional(
                                                    CONF_SCALE, default=1.0
                                                ): cv.float_,
                                                cv.Optional(
                                                    CONF_LAMBDA
                                                ): cv.returning_lambda,
                                                cv.Optional(
                                                    CONF_MAX_LENGTH
                                                ): cv.int_range(0, 254),
                                            }
                                        ),
                                        validate_attributes,
                                    ),
                                },
                            ),
                            validate_clusters,
                        ),
                    }
                ),
            ),
            cv.Optional(CONF_ON_JOIN): automation.validate_automation(
                {
                    cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(ZigBeeJoinTrigger),
                }
            ),
            cv.Optional(CONF_ON_RECALL_SCENE): automation.validate_automation(
                {
                    cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(ZigBeeRecallSceneTrigger),
                }
            ),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.require_framework_version(esp_idf=cv.Version(5, 1, 2)),
    only_on_variant(
        supported=[
            VARIANT_ESP32H2,
            VARIANT_ESP32C6,
        ]
    ),
)


def find_attr(conf, id):
    for ep in conf[CONF_ENDPOINTS]:
        for cl in ep.get(CONF_CLUSTERS, []):
            for attr in cl.get(CONF_ATTRIBUTES, []):
                if attr[CONF_ID] == id:
                    return attr
    raise EsphomeError(f"Zigbee: Cannot find attribute {id}.")


async def attributes_to_code(var, ep_num, cl):
    for attr in cl.get(CONF_ATTRIBUTES, []):
        attr_var = cg.new_Pvariable(
            attr[CONF_ID],
            var,
            ep_num,
            CLUSTER_ID.get(cl[CONF_ID], cl[CONF_ID]),
            cl[CONF_ROLE],
            attr[CONF_ATTRIBUTE_ID],
            ATTR_TYPE[attr[CONF_TYPE]],
            attr[CONF_SCALE],
        )
        await cg.register_component(attr_var, attr)

        cg.add(
            attr_var.add_attr(
                attr[CONF_ACCESS],
                attr.get(CONF_MAX_LENGTH, 0),
                attr[CONF_VALUE],
            )
        )
        if attr[CONF_REPORT]:
            cg.add(attr_var.set_report(attr[CONF_REPORT] == "force"))

        if CONF_LAMBDA in attr:
            lambda_ = await cg.process_lambda(
                attr[CONF_LAMBDA],
                [(cg.float_, "x")],
                return_type=get_c_type(attr[CONF_TYPE]),
            )

        if CONF_DEVICE in attr:
            device = await cg.get_variable(attr[CONF_DEVICE])
            template_arg = cg.TemplateArguments(get_c_type(attr[CONF_TYPE]))
            if CONF_LAMBDA in attr:
                if device.base.type.inherits_from(sensor.Sensor):
                    lambda_ = await cg.process_lambda(
                        attr[CONF_LAMBDA],
                        [(cg.float_, "x")],
                        return_type=get_c_type(attr[CONF_TYPE]),
                    )
                elif device.base.type.inherits_from(binary_sensor.BinarySensor):
                    lambda_ = await cg.process_lambda(
                        attr[CONF_LAMBDA],
                        [(cg.bool_, "x")],
                        return_type=get_c_type(attr[CONF_TYPE]),
                    )
                elif device.base.type.inherits_from(text_sensor.TextSensor):
                    lambda_ = await cg.process_lambda(
                        attr[CONF_LAMBDA],
                        [(cg.std_string, "x")],
                        return_type=get_c_type(attr[CONF_TYPE]),
                    )
                elif device.base.type.inherits_from(switch.Switch):
                    lambda_ = await cg.process_lambda(
                        attr[CONF_LAMBDA],
                        [(get_c_type(attr[CONF_TYPE]), "x")],
                        return_type=cg.bool_,
                    )
                cg.add(attr_var.connect(template_arg, device, lambda_))
            else:
                cg.add(attr_var.connect(template_arg, device))

        for conf in attr.get(CONF_ON_VALUE, []):
            trigger = cg.new_Pvariable(
                conf[CONF_TRIGGER_ID],
                cg.TemplateArguments(get_c_type(attr[CONF_TYPE])),
                attr_var,
            )
            await cg.register_component(trigger, conf)
            await automation.build_automation(
                trigger, [(get_c_type(attr[CONF_TYPE]), "x")], conf
            )


async def to_code(config):
    add_idf_component(
        name="espressif/esp-zboss-lib",
        ref="1.6.4",
    )
    add_idf_component(
        name="espressif/esp-zigbee-lib",
        ref="1.6.7",
    )
    add_idf_sdkconfig_option("CONFIG_ZB_ENABLED", True)
    if config.get(CONF_ROUTER):
        add_idf_sdkconfig_option("CONFIG_ZB_ZCZR", True)
    else:
        add_idf_sdkconfig_option("CONFIG_ZB_ZED", True)
    add_idf_sdkconfig_option("CONFIG_ZB_RADIO_NATIVE", True)
    if CONF_WIFI in CORE.config:
        add_idf_sdkconfig_option("CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE", 4096)
        cg.add_define("CONFIG_WIFI_COEX")
    if config.get(CONF_DEBUG):
        add_idf_sdkconfig_option("CONFIG_ZB_DEBUG_MODE", True)

    # create endpoints
    config, added_ids = create_ep(config, CORE.config)
    cg.add_define("ESPHOME_COMPONENT_COUNT", comp_ids + added_ids)

    # setup zigbee components
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    if CONF_MAC in config:
        # config[CONF_MAC] is MSB-first; pack into a uint64_t (octet[0] = MSB).
        # The C++ side unpacks it to the LSB-first esp_zb_ieee_addr_t expected
        # by esp_zb_set_long_address / esp_ieee802154_set_extended_address.
        mac_value = 0
        for octet in config[CONF_MAC]:
            mac_value = (mac_value << 8) | octet
        cg.add(var.set_custom_mac(mac_value))
    if CONF_TRUST_CENTER_KEY in config:
        # 16-byte key (network order) packed into two big-endian uint64_t halves
        # (key[0] = MSB of the high half). The C++ side rebuilds the uint8_t[16].
        key = config[CONF_TRUST_CENTER_KEY]
        key_hi = 0
        for octet in key[:8]:
            key_hi = (key_hi << 8) | octet
        key_lo = 0
        for octet in key[8:]:
            key_lo = (key_lo << 8) | octet
        cg.add(var.set_trust_center_key(key_hi, key_lo))
    cg.add(var.set_join_distributed(config[CONF_JOIN_MODE] == "distributed"))
    if config[CONF_LOG_NETWORK_KEY]:
        cg.add(var.set_log_network_key(True))
    if CONF_CHANNEL in config:
        chans = config[CONF_CHANNEL]
        if isinstance(chans, int):
            chans = [chans]
        mask = 0
        for ch in chans:
            mask |= 1 << ch
        cg.add(var.set_channel_mask(mask))
    if CONF_NAME not in config:
        config[CONF_NAME] = CORE.name or ""
    cg.add(
        var.set_basic_cluster(
            config[CONF_NAME],
            config[CONF_MANUFACTURER],
            config[CONF_DATE],
            config[CONF_POWER_SUPPLY],
            config[CONF_VERSION],
            config[CONF_STACK_VERSION],
            config[CONF_HW_VERSION],
            CORE.area or "",
            config[CONF_AREA],
        )
    )
    if CONF_IDENT_TIME in config:
        cg.add(var.set_ident_time(config[CONF_IDENT_TIME]))
    if CONF_MANUFACTURER_CODE in config:
        cg.add(var.set_manufacturer_code(config[CONF_MANUFACTURER_CODE]))
    if CONF_ZCL_VERSION in config:
        cg.add(var.set_zcl_version(config[CONF_ZCL_VERSION]))
    if CONF_SW_BUILD_ID in config:
        cg.add(var.set_sw_build_id(config[CONF_SW_BUILD_ID]))
    if config[CONF_MANUAL_START]:
        cg.add(var.set_manual_start(True))
    if config[CONF_HUE_EMULATION]:
        cg.add(var.set_hue_emulation(True, config[CONF_HUE_ENDPOINT]))
        # Inter-PAN del proxy d'entreteniment: la pila no te hook public; interceptem la funcio interna.
        cg.add_build_flag("-Wl,--wrap=zb_intrp_data_indication")
    for ep in config[CONF_ENDPOINTS]:
        cg.add(
            var.create_default_cluster(ep[CONF_NUM], DEVICE_ID[ep[CONF_DEVICE_TYPE]])
        )
        cg.add(
            var.add_cluster(ep[CONF_NUM], CLUSTER_ID["BASIC"], CLUSTER_ROLE["SERVER"])
        )
        if CONF_IDENT_TIME in config:
            cg.add(
                var.add_cluster(
                    ep[CONF_NUM],
                    CLUSTER_ID["IDENTIFY"],
                    CLUSTER_ROLE["SERVER"],
                )
            )
        for cl in ep.get(CONF_CLUSTERS, []):
            cg.add(
                var.add_cluster(
                    ep[CONF_NUM],
                    CLUSTER_ID.get(cl[CONF_ID], cl[CONF_ID]),
                    cl[CONF_ROLE],
                )
            )
            await attributes_to_code(var, ep[CONF_NUM], cl)

    for conf in config.get(CONF_ON_JOIN, []):
        trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trigger, [], conf)

    for conf in config.get(CONF_ON_RECALL_SCENE, []):
        trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(
            trigger, [(cg.uint16, "scene_group"), (cg.uint8, "scene_id")], conf
        )


ZIGBEE_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(ZigBeeComponent),
    }
)


@automation.register_action(
    "zigbee.reset",
    ResetZigbeeAction,
    automation.maybe_simple_id(ZIGBEE_ACTION_SCHEMA),
    # play() llama a reset() y retorna en la misma llamada -> sincrona.
    synchronous=True,
)
async def reset_zigbee_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    return var


@automation.register_action(
    "zigbee.report",
    ReportAction,
    automation.maybe_simple_id(ZIGBEE_ACTION_SCHEMA),
    synchronous=True,
)
async def report_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    return var


@automation.register_action(
    "zigbee.start",
    StartZigbeeAction,
    automation.maybe_simple_id(ZIGBEE_ACTION_SCHEMA),
    # play() llama a start() (crea el task de zigbee y retorna) -> sincrona.
    synchronous=True,
)
async def start_zigbee_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    return var


ZIGBEE_ATTRIBUTE_ACTION_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(ZigBeeAttribute),
    }
)

ZIGBEE_SET_ATTR_SCHEMA = cv.All(
    automation.maybe_simple_id(
        ZIGBEE_ATTRIBUTE_ACTION_SCHEMA.extend(
            cv.Schema(
                {
                    cv.Required(CONF_VALUE): cv.templatable(cv.valid),
                }
            )
        )
    ),
)


@automation.register_action(
    "zigbee.setAttr",
    SetAttrAction,
    ZIGBEE_SET_ATTR_SCHEMA,
    synchronous=True,
)
async def zigbee_set_attr_to_code(config, action_id, template_arg, args):
    attr = find_attr(
        CORE.config["huewejnorg"],
        config[CONF_ID],
    )
    template_arg = cg.TemplateArguments(
        get_c_type(attr[CONF_TYPE]),
        template_arg.args if template_arg.args.args else None,
    )
    parent = await cg.get_variable(config[CONF_ID])
    var = cg.new_Pvariable(action_id, template_arg, parent)
    template_ = await cg.templatable(
        config[CONF_VALUE], args, get_c_type(attr[CONF_TYPE])
    )
    cg.add(var.set_value(template_))

    return var


@automation.register_action(
    "zigbee.reportAttr",
    ReportAttrAction,
    automation.maybe_simple_id(ZIGBEE_ATTRIBUTE_ACTION_SCHEMA),
    synchronous=True,
)
async def zigbee_report_attr_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    return var
