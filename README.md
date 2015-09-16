# synfulknock

## Synopsis

This repository contains tools that can be used to actively hunt for the SYNful Knock Cisco implant in your environment.  Please use the tools responsibly.<br><br>
For more information on SYNful Knock, please see our whitepaper here:  
https://www2.fireeye.com/rs/848-DID-242/images/rpt-synful-knock.pdf

## Motivation

These tools will hopefully help you get a head start towards discovering and eradicating the Cisco implant from your environment.  We publish these with no warranty or guarantee.

## Installation

Please see readme files in each directory.

## Speed

The nmap NSE script is faster than the python script, but requires an additional NSE library (included)<br>
The size of the network will detemine which tool is most appropriate, however both can be used for sanity checks.

### NSE script
ESTIMATED WORST-CASE SPEED (THIS FACTORS IN HIGH UNUSED IP SPACE)<br>

Class C - 256 IP addresses (4 hosts up) - scanned in 2.28 seconds<br>
nmap -sS -PN -n -T4 -p 80 --script=”SYNfulKnock” 10.1.1.1/24<br>

Class B - 65536 IP addresses (4 hosts up) - scanned in 2557.50 seconds (42 min)<br>
nmap -sS -PN -n -T4 -p 80 --script=”SYNfulKnock” 10.1.1.1/16<br>

Class A - 16,777,216 IP addresses - Estimated scan time = 10,752 minutes (179 hours) = 7 days<br>
nmap -sS -PN -n -T4 -p 80 --script=”SYNfulKnock” 10.1.1.1/8<br>

### Python sript
Class C - 256 IP addresses (4 hosts up) - 59.26 seconds

## Authors

NSE script - Tony Lee<br>
Python script - Josh Homan<br><br>
For any issues, please email:  synfulknock [at] fireeye.com

## License

See license file within repository
