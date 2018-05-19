# connmon (pollere connection monitor for TCP)

_connmon_ is a linux/macOS/BSD command line tool that measures network
latency via passive monitoring of active connections and provides indications
of possible connection issues, i.e. lost or reordered packets and duplicate acks,
as well as bytes sent by flows. Like pping (https://github.com/pollere/pping),
connmon doesn't inject traffic to determine RTT (Round-Trip Time) -- it
reports the per-packet RTT experienced by normal application traffic.
Unlike transport state monitoring tools like _ss_ which can only measure
RTT at the sending endpoint, connmon can measure RTT at the sender,
receiver or anywhere on a connection's path (for example, an OpenWrt
home border router could easily monitor the RTT of all traffic to and
from the Internet).

 connmon is provided as sample code for a basic tcp connection
 monitor. It is NOT intended as production code.
 connmon operates on TCP headers, v4 or v6. It requires the
 following:
 - time of packet capture
 - packet IP source, destination, sport, and dport
 - TSval and ERC from packet TCP timestamp option
 - Seqno and Ackno
 - Size of packet payload in bytes
 - both directions of a connection
 
 The core mechanism saves the first time a TSval is seen and matches it
 with the first time that value is seen as a ERC in the reverse direction.
 The same mechanism is used to match the seqno of data packets with acknos.
 Output lines are printed on standard output with the format:

    packet capture time (time this round trip delay was observed)
    TSval-based round trip delay
    Seqno-based round trip delay
    Difference of seqno from expected seqno (helps to find holes, out-of-orders)
    Indicator of whether the packet is a duplicate ack (time since original was seen)
    Bytes in the packet payload
    Bytes seen so far in this flow
    flow in the form:  srcIP:port+dstIP:port

The seqno-based RTD is the round trip delay from the capture point to the destination host
of the flow. The sequence space holes and out-of-order packets that influence those delays
are printed out with the reverse flow, but the duplicate acks will be with the RTDs.
 
 Note that connmon produces more output than pping, close to one line per packet so a
 "quick" version (flag -Q) has been added that only prints lines when there is an RTD
 to print.
 For continued live use, output may be redirected to a file or
 piped to a display or summarization widget (see github.com/line2Chunk).


## Compiling ##

### Prerequisites

[connmon](https://github.com/pollere/connmon/) depends on
the [libtins](http://libtins.github.io/) packet parsing library
which should be [downloaded](http://libtins.github.io/download/) and
built or installed first.

connmon uses only the core functions of libtins so, if there are no other
users, a static version of the library with fewer dependencies
(only _cmake_ and _libpcap_) can be built and 'installed' in its own
source directory:
```Shell
# (assuming sources are put in ~/src)
cd ~/src
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build
cd build
cmake ../ -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 \
 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0 \
 -DCMAKE_INSTALL_PREFIX=`dirname $PWD`
make
make install
```
(The static libtins library makes the connmon binary more self-contained
so it will run on systems that don't have libtins installed.)

## Building

The connmon makefile assumes libtins has been built and installed in
directory `~/src/libtins` as described above. If that isn't the case,
edit the third line of the makefile to be the libtins install location.
For example, if the libtins precompiled binary is installed, change the
third line to:
```Shell
LIBTINS = /usr/local
```
Nothing else in Makefile should require changing and just typing `make`
should build connmon.

There's currently no _install_ target in the makefile because connmon
for live traffic (as opposed to running it on a pcap file)
requires packet sniffing capabilities and there's no standard way
to set that up (see the notes on "Reading packets from a network
interface" in `man pcap`). It can always be run as root via `sudo`.

## Examples ##

`connmon -i` _interface_ `  ` monitors tcp traffic on _interface_ and reports
each packet's RTT to stdout. For example
   `connmon -i en0    ` (Mac OS)
   `connmon -i wlp2s0 ` (Ubuntu 17.04)

`connmon -r` _pcapfile_ `  ` prints the RTT of tcp packets captured
with _tcpdump_ or _wireshark_ to _pcapfile_.

There are a few flags that control how long connmon will capture and/or how
many packets it will capture, the output format, and a bpf filter for
what packets to capture. For example, to see the RTT of next 100
tcp packets from netflix or youtube:
```Shell
   connmon -i en0 -c 100 -f 'net 45.57 or 74.125'
```
`connmon -h`, `connmon --help`, or just `connmon` describes the flags.

Since connmon outputs one line per packet, if it's being run on a busy
interface its output should be redirected to a file or piped to a
summarization or plotting utility. In the latter case, the `-m`
(machine-friendly output format) might be useful.

