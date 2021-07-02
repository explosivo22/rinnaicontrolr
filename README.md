# rinnaicontrolr - Python interface for the Rinnai Control-R API

[![PyPi](https://img.shields.io/pypi/v/rinnaicontrolr?style=for-the-badge)](https://pypi.python.org/pypi/rinnaicontrolr)
[![License](https://img.shields.io/github/license/explosivo22/rinnaicontrolr?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)

Python library for communicating with the [Rinnai Control-R Water Heaters and control devices](https://www.rinnai.us/tankless-water-heater/accessories/wifi) via the Rinnai Control-R cloud API.

Rinnai's API is completely insecure. We recommend that you disconnect your water heater
from the Control-R system until Rinnai fixes these basic issues.

This library is community supported. Please submit changes and improvements.

## Support For

- reading and setting the temperature setpoint
- reading whether heating or recirculation is in progress
- starting recirculation

## Limited Support For

- reading schedules, vacation state
- reading flow rates and service parameters
- reading intake temperature, outlet temperature
- reading the address of the device as entered into Control-R

## No Support For

- creating schedules
- setting vacation state

Please submit pull requests to add support for your favorite values.

## Installation

```
pip install rinnaicontrolr
```

## Example

```python
rinnai = RinnaiWaterHeater(username, password)
for device in rinnai.get_devices():
    rinnai.set_temperature_setpoint(device, 90) # make it annoyingly cold
    rinnai.start_recirculation(device, 15) # start recirculation for 15 minutes
    if rinnai.is_heating(device):
        print(f'heater is heating to a setpoint of {rinnai.get_temperature_setpoint(device)} degrees.')
```

## Known Issues

* Rinnai's API performs no authentication. Sorry, we can't fix this, we don't work for Rinnai.

## Future Plans

* Perform authentication once Rinnai's API requires it.
* asyncio interface.
