# Introduction

MISP-to-EIQ is a simple Python script that will connect to your MISP instance,
download the given MISP Event ID and send it to an EclecticIQ instance as a
valid EclecticIQ JSON entity of the STIX 'Indicator' type.

For configuration options, refer to the README.md in the config/ directory.

# Requirements

- Python 3 (uses 'requests', 'urllib3', 'datetime')
- EIQlib module from Sebastiaan Groot (eiqjson.py and eiqcalls.py)
- A MISP account with a valid API token
- An EclecticIQ account (user+pass) and EIQ 'Source' token

# Getting started

- Clone the repository
- Create a 'settings.py' file in the config/ directory (refer to the README.md)
- Run ./misp-to-eiq.py [-v] <#> (-v for verbose, # should be a valid MISP Event ID)

# Options

Running ./misp-to-eiq.py without command-line options or `-h` will display help:  
  
-v / --verbose will display progress/error info
-c / --confidence lets you set the confidence level for the EclecticIQ entity
-i / --impact lets you set the (likely) impact for the EclecticIQ entity
-t / --type lets you choose what to ingest the MISP event as: [i]ndicator or [s]ighting

# Copyright

(c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
<sebastiaang _monkeytail_ kpn-cert.nl> (for his great EIQ lib / submodule)
  
This software is GPLv3 licensed, except where otherwise indicated.
