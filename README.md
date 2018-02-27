# DNS Spoofer

This application is written in C code for a Linux operating system. It is a DNS spoofer that can do its
own man in the middle attack and manually forwards packets. The way that it works is by intercepting the servers DNS
response, change it to whatever is specified by the configuration file, then send it to the client.

This application also scan a network by using a netmask to send an ARP request to each machine. It
then waits for the responses and assembles a list of all machines on the subnet, along with their MAC
addresses.

You are also able to specify an interface to run the program on. If one is not specified it will try to use
the first one it finds.

When the man in the middle attack is used, the spoofer will send an ARP response every 5 seconds to
each of the victim machines telling them that the attacker machine is the other victim.


## Usage
./dns_spoofer -h -s <netmask> -l -i <interface> -c <config> -m <Victim IP 1> <Victim IP 2>

	 -h --help: Displays this message.
	 
	 -s --scan: Scans the for all computers with the specified netmask. Ex: 192.168.0.0/24
	 
	 -l --if-list: Prints a list of all of the interfaces on the computer.
	 
	 -i --interface: Specifies an interface for the application to use. If this parameter is not specified, the first one on the list will be chosen.
	 
	 -c --config: Specifies the config file for the DNS spoof.
	 
	 -m --mitm: Performs a man in the middle attack as well as the DNS spoof.


## Examples

Scanning for computers on a network:

./dns_spoofer -s 192.168.0.0/24

Listing the interfaces:

./dns_spoofer -l

Running the config file:

./dns_spoofer -c config 192.168.0.5 192.168.0.6

Running the config file with a man in the middle attack:

./dns_spoofer -m -c config 192.168.0.5 192.168.0.6