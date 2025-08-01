# Python_Ping_Sweep
Python script to perfom a ping sweep for given subnet

Simple Python script to take a subnet / IP range and perform a ping sweep.
The ICMP active hosts are saved to a text file which can then be parsed into python portscanner.

REQUIREMENTS:

scapy
(pip install scapy)

Using pipx to install system wide and outside of env.

python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install scapy

USAGE:

python3 pingsweep.py Target {subnet/range/single IP (e.g. 192.168.1.0/24, 192.168.1.1)}
