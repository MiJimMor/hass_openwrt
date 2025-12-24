# Changelog

All notable changes to this project will be documented in this file.

<!--next-version-placeholder-->
## v0.3.0 **Forked from [kvj/hass_openwrt](https://github.com/kvj/hass_openwrt)**

## Recent changes
New sensors:
  * Wireless clients counters (per interface/SSID) with client details (signal, IP, name)
  * Wireless total clients (aggregate across interfaces)
  * Known hosts sensor (lists IP, name and MAC)
  * System sensors: uptime, load and memory (swap/disk usage when available)

Several improvements and fixes have been added to make the integration more resilient:

- **Wireless discovery fallback**: if the `network.wireless` API is available but the `discover_wireless()` function fails at runtime, the alternative `discover_wireless_uci()` (UCI `wireless` get) is automatically attempted. Relevant log messages:

  - `discover_wireless failed, trying UCI fallback: ...`
  - `discover_wireless_uci fallback failed, using empty result: ...`

  See changes in: [custom_components/openwrt/coordinator.py](custom_components/openwrt/coordinator.py#L571-L576)

- **Validation of `mwan3` entries**: when creating sensors, invalid `mwan3` entries (not dicts, missing `uptime_sec`/`online_sec`, or non-numeric) are automatically ignored and a warning is logged. This prevents creating sensors with incorrect data or causing errors.

  Relevant log messages:

  - `Skipping mwan3 entry '<id>' for device <device_id>: data is not a dict`
  - `Skipping mwan3 entry '<id>' for device <device_id>: invalid data (<error>)`

  See changes in: [custom_components/openwrt/sensor.py](custom_components/openwrt/sensor.py#L58-L76)

- **Ubus improvements (logging and error handling)**: more detailed debug messages were added for RPC calls and error-to-exception mapping was improved (`PermissionError`, `NameError`, `ConnectionError`). Useful log messages:

  - `Starting api_call with subsystem: ...`
  - `Login result: ...` / `ACLs: ...`
  - `api_call exception: ...`

  See changes in: [custom_components/openwrt/ubus.py](custom_components/openwrt/ubus.py#L39)

## v0.0.2

- Add service management using command
- Add service translations to English language
- Added French translation

## v0.0.1

First version.
