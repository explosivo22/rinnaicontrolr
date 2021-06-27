"""
rinnaicontrolr -- Python client for the Rinnai API

RinnaiWaterHeater provides methods to access and set water heater
parameters: e.g.
   wh = RinnaiWaterHeater('your_rinnai_app_email@email.com',
                          'your_rinnai_app_password')
   for device in wh.get_devices():
      pass # device is a dictionary of parameters
   wh.start_recirculation(...)

Important: The Rinnai API is severely rate limited. It seems to accept
queries every 10 minutes or so, but not much more often.
   
"""

from rinnaicontrolr.base import RinnaiWaterHeater

# we told you it was a simple API...
