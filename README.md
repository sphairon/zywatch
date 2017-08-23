# zywatch
Zywatch is a bash script used for Friendly User Test (FUT) field monitoring of Zyxel CPEs.

# usage
```
cd /usr/local/source/
git clone https://github.com/sphairon/zywatch.git
cd zywatch
./zywatch.sh setup
editor /etc/zy.conf
```

update at least the following config parameters within /etc/zy.conf:

* DUTUSER
* DUTPASS
* DYNDNS1
* DYNDNS2
* MONITORINGPASSWD
* DIAL (if modem is connected)

Afterwards the script will run once every 10 minutes and report
DSL CPE status to a monitoring server

# Currently this tests are supported
* IPv4 WAN connectivity
* IPv6 WAN connectivity
* DNS resolving
* up to two DynDNS domains are up to date
* DUT GUI is accessible and responds within a given time
* SIP accounts are registered
* Software version of DUT is up-to-date
* overall system satus of DUT is OK (no failed services)
* check script version is up-to-date
