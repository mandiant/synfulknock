local bin = require "bin"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet2"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Tests for the presence of a Cisco Implant.  Steps are described below:

Step 1) Sends TCP SYN packet to port 80.  seq and ack difference of 0xC123D (Decimal: 791101).
Step 2) Checks TCP SYN/ACK packet response for seq and ack difference of 0xC123E (Decimal: 791102).
Step 3) Checks TCP SYN/ACK TCP flags for:  02 04 05 b4 01 01 04 02 01 03 03 05
]]

---
-- @usage
-- nmap --script SYNfulKnock [--script-args reportclean=1] target
-- @args probeport Report clean hosts as well as dirty
-- @output
-- Host script results:
-- | SYNfulKnock: 
-- | seq = 0x7528092b
-- | ack = 0x75341b69
-- | diff = 0xc123e
-- | Result:  Handshake confirmed.  Checking flags.
-- | TCP flags: 2 04 05 b4 1 01 04 02 1 03 03 05
-- |_Result:  Flags match.  Confirmed infected!

-- This script requires modifying nselib packet to add ability to set ack values

author = "Tony.Lee@Mandiant.com"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

local scanport

--- Pcap check function
-- @return Destination and source IP addresses and TCP ports
local check = function(layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return bin.pack('AA=S=S', ip.ip_bin_dst, ip.ip_bin_src, ip.tcp_dport, ip.tcp_sport)
end

--- Updates a TCP Packet object
-- @param tcp The TCP object
-- Random source port, random ack, and seq number is 0xC123D higher than ack
local updatepkt = function(tcp)
  tcp:tcp_set_sport(math.random(0x401, 0xffff))
  local ack = math.random(1, 0x7fffffff) 
  local seq = ack + 0xC123D
  tcp:tcp_set_seq(seq)
  tcp:tcp_set_ack(ack)
  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
end

--- Create a TCP Packet object
-- @param host Host object
-- @param port Port number
-- @return TCP Packet object
local genericpkt = function(host, port)
  local pkt = bin.pack("H",
  "4500 002c 55d1 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  tcp:tcp_set_dport(port)

  updatepkt(tcp)

  return tcp
end

--- Processes results from SYN/ACK to determine if the router is infected
-- @param responsefields - seq, ack, and tcp flags
local processresponse = function(layer3, host)
  local reportclean = stdnse.get_script_args("implanttest.reportclean")
  seq = packet.u32(layer3, 24)
  stdnse.print_debug("seq is:  %s=0x%s", packet.u32(layer3, 24), stdnse.tohex(packet.u32(layer3, 24)))
  ack = packet.u32(layer3, 28)
  stdnse.print_debug("ack is:  %s=0x%s", packet.u32(layer3, 28), stdnse.tohex(packet.u32(layer3, 28)))

  local output = "\r\nseq = 0x" .. stdnse.tohex(seq)
  output = output .. "\r\nack = 0x" .. stdnse.tohex(ack)
  if ack > seq then
    dif = ack - seq
  else
    dif = seq -ack
  end

  output = output .. "\r\ndiff = 0x" .. stdnse.tohex(dif)
  if dif == 791102 then
    output = output .. "\r\nResult:  Handshake confirmed.  Checking flags."
    local tcpflags1 = packet.u32(layer3, 40)
    stdnse.print_debug("tcpflags1 is:  %s", tcpflags1)
    local tcpflags2 = packet.u32(layer3, 44)
    stdnse.print_debug("tcpflags2 is:  %s", tcpflags2)
    local tcpflags3 = packet.u32(layer3, 48)
    stdnse.print_debug("tcpflags3 is:  %s", tcpflags3)
    output = output .. "\r\nTCP flags: " .. stdnse.tohex(tcpflags1, {separator = " ", group = 2}) .. " " .. stdnse.tohex(tcpflags2, {separator = " ", group = 2}) .. " " .. stdnse.tohex(tcpflags3, {separator = " ", group = 2})
    if tcpflags1 == 33818036 and tcpflags2 == 16843778 and tcpflags3 == 16974597 then
      output = output .. "\r\nResult:  Flags match.  Confirmed.\r\nInfected:" .. packet.toip(host.bin_ip)
    else
      output = output .. "\r\nResult:  Flags don't match!  May not be infected."
    end
  else
    stdnse.print_debug("reportclean is:  %s", reportclean)
    if reportclean == "1" then
      output = output .. "\r\nResult:  Not infected"
    else
      output = ""
    end
  end
  
  return output
end


portrule = function(host)
  if not nmap.is_privileged() then
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    if not nmap.registry[SCRIPT_NAME].rootfail then
      stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
    end
    nmap.registry[SCRIPT_NAME].rootfail = true
    return nil
  end

  if nmap.address_family() ~= 'inet' then
    stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
    return false
  end
  if not host.interface then
    return false
  end
  scanport = 80
  return (scanport ~= nil)
end

action = function(host)
  local i = 1
  local responsefields = {}
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = packet.toip(host.bin_ip_src)
  local daddr = packet.toip(host.bin_ip)
  local try = nmap.new_try()

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  pcap:pcap_open(host.interface, 104, false, "tcp and dst host " .. saddr .. " and src host " .. daddr .. " and src port " .. scanport)

  pcap:set_timeout(host.times.timeout * 1000)

  local tcp = genericpkt(host, scanport)

  try(sock:ip_send(tcp.buf, host))
  local status, len, _, layer3 = pcap:pcap_receive()
  local test = bin.pack('AA=S=S', tcp.ip_bin_src, tcp.ip_bin_dst, tcp.tcp_sport, tcp.tcp_dport)

  pcap:close()
  sock:ip_close()

  local output = processresponse(layer3, host)

  if nmap.debugging() > 0 then
    output = output
  end

  return output
end

