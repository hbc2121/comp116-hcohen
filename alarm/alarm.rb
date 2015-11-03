#Hayley Cohen
#Assignment 2

require 'packetfu'
require 'rubygems'

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
	check = pkt.scan(/nmap/i)

	if check.length > 0 
		 return true
	else
		return false
	end
end


#if the packet has the syntax and details of the credit card, then there was a credit card leak
def CREDIT_CARD? (pkt)

####TO DO#####

end

#NIKTO
def NIKTO? (pkt)

####TO DO #####

end
#print the alert messge
def alert(pkt, incident, num)
	print "{num}. ALERT: #{incident} is detected from #{pkt.ip_sadder} #{pkt.proto.last} #{pkt.payload}!\n"
end

#main analysis of the packet
def cap_analyze ()

	cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	num = 0

	cap.cap.each do |p|
	pkt = PacketFu::Packet.parse p

	if NULL? pkt
		num = num + 1
		alert pkt, "NULL scan", num
		next

	if FIN? pkt
		num = num + 1 
		alert pkt, "FIN scan", num
		next

	if XMAS? pkt
		num = num + 1
		alert pkt, "XMAS scan", num
		next

	if NMAP? pkt	
		num = num + 1
		alert pkt "NMAP scan", num
		next
	
	if CREDIT_CARD? pkt
		num = num + 1
		print "ALERT: Credit card leaked in the clear form from #{pkt.ip_sadder} 
		#{pkt.proto.last} #{pkt.payload}!\n"
		next

	if NIKTO? pkt
		num = num + 1
		alert pkt "Nikto Scan", num
		next
	end
end
