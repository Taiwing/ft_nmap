# ft\_nmap

This is a re-implementation of the nmap utility in C. This program acts as a
network scanner and a port mapper. It can be used to diagnostic networking
issues or to gather infromations on a given network in an offensive security
setting.

<br />
<p align="center">
	<img src="https://github.com/Taiwing/ft_nmap/blob/master/resources/eye.png?raw=true" alt="eye" style="width: 50%;" />
</p>

## Setup

```shell
# clone it with the libft submodule
git clone --recurse-submodules https://github.com/Taiwing/ft_nmap
# build it
cd ft_nmap/ && make
# run it
sudo ./ft_nmap example.com
```

As shown above this program needs sudo rights. This is because ft\_nmap uses raw
sockets for crafting custom ip packets and read responses. If you do not have
root access on your machine but docker is available, then execute the following
commands to run ft\_nmap:

```shell
# build docker image and run it
./setup-docker.bash
# run ft_nmap inside the container
./ft_nmap example.com
```

## Usage

```
Usage:
	ft_nmap [-dhv46] [-f file_path] [-i interface] [-p port_list] [-S speedup]
		[-s scan_list] [--complete | --heatmap | --range]
		[--max-retries retries] [--scan-delay time]
		[--initial-rtt-timeout time] [--min-rtt-timeout time]
		[--max-rtt-timeout time] [--disable-backoff] [--disable-ping]
		[--skip-non-responsive] [--adventure | --web-adventure] host ...

Options:
	-d, --debug
		Show debugging information about posix threads and ft_nmap tasks. Also
		print packets that do not match any valid probe (filter failures).
	-f, --file
		File containing a list of hosts to scan (1 per line).
	-h, --help
		Print this and exit.
	-i, --interface
		Select interface on which to listen on.
	-p, --ports
		Ports to scan specified as a comma separated list of individual ports or
		ranges (eg: 80,22,1024-2048). The default is 1-1024.
	-S, --speedup
		Number of parallel threads to use (def: 0, min: 0, max: 250).
	-s, --scan
		Scans to perform specified as a comma separated list. Possible values:
		'SYN/ACK/NULL/FIN/XMAS/UDP' (eg: SYN,UDP). It is possible to only
		use one letter by scan (eg: '-sA' for ACK). Does them all by default.
	-v, --verbose
		Show probe packets, replies and timeouts.
	-4, --ipv4
		Use only IPv4.
	-6, --ipv6
		Use only IPv6.
	--complete
		Show every port and scan type in the final host report. It has no effect
		if used with an other report mode than the default.
	--heatmap
		Heatmap report. Shows a heat map of every port in a grid. Ports go from
		red to green depending on how filtered or open they are.
	--range
		Range report. This will show each scan as a range of ports on every
		outcome state instead of the default port table.
	--max-retries
		Set max number of retries to for sending a probe (def: 10, min: 0, max: 100).
	--scan-delay
		Adjust delay between probes.
	--initial-rtt-timeout
		Set initial time to wait for a probe to respond before retry or timeout.
	--min-rtt-timeout
		Set minimum value of the RTT timeout.
	--max-rtt-timeout
		Set maximum value of the RTT timeout.
	--disable-backoff
		Disable UDP probe backoff in case of ICMP rate limit.
	--disable-ping
		Disable ping echo scans.
	--skip-non-responsive
		Skip hosts that do not respond to echo scans.
	--adventure
		Find random responding hosts and scan them. Adventure mode will start
		when ft_nmap is done scanning the hosts provided as arguments and in
		the file if any. NOTE: works best with IPv4 flag (IPv6 hosts are
		really hard to find at random)
	--web-adventure
		Same as adventure mode but only on hosts listening on port 80 and 443.
```

#### example:

```shell
# execute every scan type on the first 1024 ports of google.com
./ft_nmap google.com
```

possible output:

```
--- Network ---
IPv4 Status: on
IPv6 Status: on
Default Interface: tap0

--- Scan ---
Number of threads: 0
Number of ports to scan: 1024
Scans to be performed: SYN ACK NULL FIN XMAS UDP

Host: google.com
Scan took 5.61052 seconds
IP address: 142.250.179.78
Ports not shown: 1022 Closed

Open ports:
| Port  | Service              | SYN  | ACK  | NULL | FIN  | XMAS | UDP  |
--------------------------------------------------------------------------
| 80    | http                 | O    | U    | C    | C    | C    | OF   |
| 443   | https                | O    | U    | C    | C    | C    | OF   |

--- ft_nmap done ---
1 address scanned in 5.65263 seconds
```

## Description

The host arguments can either be IPv4, IPv6 addresses, hosts as defined
in the /etc/hosts file or domain names. ft\_nmap will loop on them until
no argument is left. Then it will look at the --file option value if it
was given and do the same. The host file format is one host per line.

Options that take a 'time' value are in milliseconds by default. They
can be appended a time unit which will be one of: us (microseconds),
ms (milliseconds), s (seconds), m (minutes) or h (hours).

## Adventure mode

The --adventure and --web-adventure options allow the user to scan random hosts.
ft\_nmap will generate a lot of random ips and scan them until it gets replies.
This is an other form of target specification, like providing a host as an
argument or reading a host list from a file. ft\_nmap will keep on scanning
until it is stopped by the user (with a Ctrl+C). When a responding host is found
ft\_nmap will execute the scans requested by the user.

The difference between --adventure mode and --web-adventure mode is that the
first one uses a ping scan to detect hosts. The --web-adventure will only select
hosts that are actively listening on the http and https ports (80 and 443).

> This feature technically works with IPv6. By default it will generate both
> IPv4 and IPv6 addresses but this is not recommended. These options should only
> be used with IPv4 (so the -4 option). It is much easier to find hosts in the
> IPv4 address space because of
> [how saturated it is](https://en.wikipedia.org/wiki/IPv4_address_exhaustion).

#### example:

```shell
# executing an IPv4 SYN scan on random web servers
./ft_nmap -4 -sS --web-adventure
```

possible output:

```
--- Network ---
IPv4 Status: on
IPv6 Status: off
Default Interface: tap0

--- Scan ---
Number of threads: 0
Number of ports to scan: 1024
Scans to be performed: SYN

Host: 18.155.95.119
Scan took 5.77588 seconds
IP address: 18.155.95.119
Ports not shown: 1022 Filtered

Open ports:
| Port  | Service              | SYN  |
---------------------------------------
| 80    | http                 | O    |
| 443   | https                | O    |

Host: 35.157.184.38
Scan took 7.61362 seconds
IP address: 35.157.184.38
Ports not shown: 1022 Filtered

Open ports:
| Port  | Service              | SYN  |
---------------------------------------
| 80    | http                 | O    |
| 443   | https                | O    |
```

## Scan states

Each scan type given in scan list is a column in the final host report
and a series of letters is used to describe the result of a port scan:

- O --> Open
- C --> Closed
- U --> Unfiltered
- F --> Filtered
- OF --> Open|Filtered

### Open

An application is actively listening on the given port. It expects TCP or UDP
packets to initiate a connection in order to interact with the host. Finding
these type of ports is the primary goal of a security scan. Each open port is a
potential vulnerability that could be exploited by an attacker.

### Closed

The given port is responding to user requests but no application is listening on
it. This can be useful for host detection (confirming that a host is up) or for
OS detection (as different OS will typically have different open/closed/filtered
ports schemes by default). Closed ports might also be checked again later as a
service could be started after the scan.

### Unfiltered

This state can only be obtained on ACK scans. If a RST response is sent in reply
to an ACK scan then the port is not filtered. This means that the port is
not blocked by a firewall and can therefore be reached. The information is not
precise but it is easy and fast to obtain.

### Filtered

The port is not responsive or is returning an ICMP error indicating a violation
of some network policy. This typically means that a firewall has been set up on
the targeted host, or on a router or that a system limit has been reached.

### Open | Filtered

This means that the given scan has not received any response for a UDP or
NULL/FIN/XMAS scan. ft\_nmap is not able to say if the port is opened or if it
has been filtered.

## Scan Types

### SYN

Initiate a TCP connection by sending a TCP packet with the SYN bit set. This can
result in an Open state for the TCP port.

Possible responses and states:
- Open --> tcp SYN or tcp SYN/ACK
- Closed --> tcp RST
- Filtered --> icmp type 3 code 0/1/2/3/9/10/13 or timeout

### ACK

Send an ACK packet out of the blue which can only be responded to by a RST
packet, an error or a timeout. This is a fast scan that makes it easy to detect
a protected host.

Possible responses and states:
- Unfiltered --> tcp RST
- Filtered --> icmp type 3 code 0/1/2/3/9/10/13 or timeout

### UDP

Try to initiate a UDP connection on the given port. This is the hardest type of
scan as listening UDP services are rarer than TCP and also tend to be more
protected. Also UDP applications will typically not respond if the UDP packet
initiating the connection does respect not the specific service's protocol. This
means that different probes must be sent for each possible service on each port.

Possible responses and states:
- Open --> udp
- Closed --> icmp type 3 code 3
- Filtered --> icmp type 3 code 0/1/2/9/10/13
- Open|Filetered --> timeout

### NULL, FIN, XMAS

Try to elicit an RST response to check if a port is closed. This scan cannot
return an open state as the TCP packet being sent is not valid. This is a sneaky
way to possibly skip some firewall rules and obtain more information than with
an ACK scan.

Possible responses and states:
- Closed --> tcp RST
- Filtered --> icmp type 3 code 0/1/2/3/9/10/13
- Open|Filetered --> timeout
