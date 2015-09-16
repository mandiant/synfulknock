# synfulknock

## Synopsis

This repository contains tools that can be used to actively hunt for the SYNful Knock Cisco implant in your environment.  Please use the tools responsibly.<br><br>
For more information on SYNful Knock, please see our whitepaper here:  
https://www2.fireeye.com/rs/848-DID-242/images/rpt-synful-knock.pdf

## Motivation

These tools will hopefully help you get a head start towards discovering and eradicating the Cisco implant from your environment.  We publish these with no warranty or guarantee.

## Installation

Please see readme files in each directory.<br>
**Note:  The NSE script was tested on a Kali 2.0 & Ubuntu 15.04 VM--other distros may have strange dependency issues**

### Kali 2.0 ###
Nothing special required

cp synfulknock.nse /usr/share/nmap/scripts/<br>
cp packet2.lua /usr/share/nmap/nselib/<br>

### 64-bit Ubuntu 15.04

wget https://nmap.org/dist/nmap-6.49BETA4-1.x86_64.rpm<br>
apt-get install alien<br>
alien nmap-6.49BETA4-1.x86_64.rpm<br>
dpkg --install nmap_6.49BETA4-2_amd64.deb<br>

apt-get install subversion<br>
ln -s /usr/lib/x86_64-linux-gnu/libsvn_client-1.so.1 /usr/lib/libsvn_client-1.so.0<br>

cp synfulknock.nse /usr/share/nmap/scripts/<br>
cp packet2.lua /usr/share/nmap/nselib/<br>

## Contributions

This research is ongoing, but if you would like to contribute please email us at:  synfulknock [at] fireeye.com

## Speed

The nmap NSE script is faster than the python script, but requires an additional NSE library (included)<br>
The size of the network will determine which tool is most appropriate, however both can be used for sanity checks.

### NSE script
ESTIMATED WORST-CASE SPEED (THIS FACTORS IN HIGH UNUSED IP SPACE)<br>

Class C - 256 IP addresses - Estimated scan time = 2.28 seconds<br>
nmap -sS -PN -n -T4 -p 80 --script="SYNfulKnock" 10.1.1.1/24<br>

Class B - 65536 IP addresses - Estimated scan time = 2557.50 seconds (42 min)<br>
nmap -sS -PN -n -T4 -p 80 --script="SYNfulKnock" 10.1.1.1/16<br>

Class A - 16,777,216 IP addresses - Estimated scan time = 10,752 minutes (179 hours) = 7 days<br>
nmap -sS -PN -n -T4 -p 80 --script="SYNfulKnock" 10.1.1.1/8<br>

### Python script
Class C - 256 IP addresses (4 hosts up) - 59.26 seconds

## Sample Syntax and Output

## NSE script
nmap -sS -PN -n -T4 -p 80 --script="SYNfulKnock" 10.1.1.1/24

-- | SYNfulKnock:<br>
-- | seq = 0x7528092b<br>
-- | ack = 0x75341b69<br>
-- | diff = 0xc123e<br>
-- | Result:  Handshake confirmed.  Checking flags.<br>
-- | TCP flags: 2 04 05 b4 1 01 04 02 1 03 03 05<br>
-- |_Result:  Flags match.  Confirmed infected!<br>


### Python script
python ./trigger_scanner_sniff.py -d 10.1.1.1/10.1.1.2<br>
2015-07-14 12:59:02,760 190 INFO    Sniffer daemon started<br>
2015-07-14 12:59:02,761 218 INFO    Sending 2 syn packets with 10 threads<br>
2015-07-14 12:59:03,188 110 INFO    10.1.1.1:80 - Found implant seq: 667f6e09 ack: 66735bcd<br>
2015-07-14 12:59:03,190 225 INFO    Waiting to complete send<br>
2015-07-14 12:59:03,190 227 INFO    All packets sent<br>

## Authors

NSE script - Tony Lee<br>
Python script - Josh Homan<br><br>
For any issues, please email:  synfulknock [at] fireeye.com

## License

See license file within repository
