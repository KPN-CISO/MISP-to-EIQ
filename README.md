# Introduction

MISP-to-EIQ is a simple Python script that will connect to your MISP instance,
download the given MISP Event ID and send it to an EclecticIQ instance as a
valid EclecticIQ JSON entity of the given type.

We consider the code to be stable enough to use in production. While it is not
possible to test for every combination of MISP objects & attributes, MISP-to-EIQ
has been running in our production environment for longer periods without any
significant problems/issues/crashes.

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
  
`-v` / `--verbose` will display progress/error info  
`-c` / `--confidence` lets you set the confidence level for the EclecticIQ entity  
`-i` / `--impact` lets you set the (likely) impact for the EclecticIQ entity  
`-t` / `--type` lets you choose what to ingest the MISP event as: [i]ndicator or [s]ighting  
`-s` / `--simulate` do not actually ingest anything into EclecticIQ, just pretend (useful with `-v`)  
`-n` / `--name` override the default TITLETAG setting from the configuration file  
`-d` / `--duplicate` do not update the existing entity in EclecticIQ, but create duplicates (default: disabled)  

# Copyright

(c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
<sebastiaang _monkeytail_ kpn-cert.nl> (for his great EIQ lib / submodule)
  
This software is GPLv3 licensed, except where otherwise indicated.
