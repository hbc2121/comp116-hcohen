#Hayley Cohen
#Assignment 2

require 'packetfu'
require 'rubygems'

#if there are no flags, the scan is null
def NULL? (pkt)

	if  pkt.tcp_flags.ack == 0 && pkt.tcp_flags.fin == 0 && pkt.tcp_flags.psh == 0
		pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.urg == 0

		return true
	else
		return false
	end

end

#if there is a fin flag, then there was a fin scan
def FIN?(pkt)

	if pkt.tcp_flags.ack == 0 && pkt.tcp_flags.fin == 1 && pkt.tcp_flags.psh == 0
       pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.urg == 0
		
		return true
	else
		return false
	end
end


#if there is a fin, psh, and urg flag, then there was an xmas scan
def XMAS?(pkt)

	if pkt.tcp_flags.ack == 0 && pkt.tcp_flags.fin == 1 && pkt.tcp_flags.psh == 1
       pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.urg == 1
		
		return true
	else
		return false
	end
end

#if nmap appears in the payload, then there was an nmap scan
def NMAP?(pkt)

	payload = pkt.payload
	check = pkt.scan(/\x4E\x6D\x61\x70/)

	if check.length > 0 
		 return true
	else
		return false
	end
end


#if the packet has the syntax and details of the credit card, then there was a credit card leak
def CREDIT_CARD? (pkt)

#need to check for the 4 different formats of the 
	info = pkt.tcp_header.body
	visa = info.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
	master = info.scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
	discover = info.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
	amer = info.scan(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/i)

	if visa > 0 || master > 0 || discover > 0 || amer > 0
		return true
	else
		return false
	end		
end

#NIKTO
def NIKTO? (pkt)

	payload = pkt.payload
	check = pkt.scan(/\x4E\x69\x6B\x74\x6F/)

	if check.length > 0 
		 return true
	else
		return false
	end
end

#print the alert messge
def alert(pkt, incident, num)
	print "{num}. ALERT: #{incident} is detected from #{pkt.ip_sadder} #{pkt.proto.last} #{pkt.payload}!\n"
end

#main analysis of the packet
	stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	num = 0

	stream.stream.each do |p|
	pkt = PacketFu::Packet.parse p

	if NULL? pkt
		num = num + 1
		alert pkt, "NULL scan", num

	if FIN? pkt
		num = num + 1 
		alert pkt, "FIN scan", num

	if XMAS? pkt
		num = num + 1
		alert pkt, "XMAS scan", num

	if NMAP? pkt	
		num = num + 1
		alert pkt "NMAP scan", num
	
	if CREDIT_CARD? pkt
		num = num + 1
		print "ALERT: Credit card leaked in the clear form from #{pkt.ip_sadder} 
		#{pkt.proto.last} #{pkt.payload}!\n"

	if NIKTO? pkt
		num = num + 1
		alert pkt "Nikto Scan", num
	end
end


