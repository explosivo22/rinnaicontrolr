# rinnaicontrolr - Python interface for the Rinnai Control-R API

[![PyPi](https://img.shields.io/pypi/v/rinnaicontrolr?style=for-the-badge)](https://pypi.python.org/pypi/rinnaicontrolr)
[![License](https://img.shields.io/github/license/explosivo22/rinnaicontrolr?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)

Python library for communicating with the [Rinnai Control-R Water Heaters and control devices](https://www.rinnai.us/tankless-water-heater/accessories/wifi) via the Rinnai Control-R cloud API.

NOTE:

* This library is community supported, please submit changes and improvements.
* This is a very basic interface, not well thought out at this point, but works for the use cases that initially prompted spitting this out from.

## Supports

- current temperature

## Installation

```
pip install rinnaicontrolr
```

## Examples

```python
rinnai = RinnaiWaterHeater(username, password)
rinnai.getDevices
```

## Known Issues

* not all APIs supported
