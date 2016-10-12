# easySig
easySig is a tailored-miniversion of moniSig, designed for schedulable monitoring ip packages easily

# Functions
- To capture the ip packages on user-specified device or any device.
- To capture the ip packages in user-specified time window.

# Usage guide:
- Download all of source files in the directory "src".
- Run "make" to build the executable file, default name is easySig.
- Run easySig with the arguments: easySig "device name" (# of packets) (seconds) "filter string"

# Notes:
- "device name": specified dev or "\*" for any device.
- (# of packets): 0 for unlimited packages to be monitored.
- (seconds): monitoring time window.
- "filter string": see PCAP lib.

# Example:
- To capture the ip packages on any device, without package number limitation, only for 30 seconds, and the port is 5678 and ToS value should be 0x20.
```
./easySig "*" 0 30 "(port 5678) and (ip[1] & 0xfc ==0x20)"
```

> Contact information: Shirley.Mosverkstad@gmail.com
