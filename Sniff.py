from scapy.all import *
import unittest
import netinfo
import threading
import Queue

default_gateway = [route for route in netinfo.get_routes() if route['dest'] == '0.0.0.0'][0]['dev']

class TestSequenceFunctions(unittest.TestCase):

	#Sniffing TCP packets for 30 seconds
	def test_tcp(self):

		res=sniff(filter="tcp", iface=default_gateway, timeout=10)
		self.assertTrue(len(res) >= 10, 'TCP = '+str(len(res)))
		wrpcap('test_tcp_log.pcap', res)

	#Sniffing ICMP packets for 30 seconds
	def test_icmp(self):

		res=sniff(filter="icmp", iface=default_gateway, timeout=30)
		self.assertTrue(len(res) >= 10, 'ICMP = '+str(len(res)))
		wrpcap('test_icmp_log.pcap', res)

	#Sniffing UDP packets for 30 seconds
	def test_udp(self):

		res=sniff(filter="udp", iface=default_gateway, timeout=30)
		self.assertTrue(len(res) >= 50, 'UDP = '+str(len(res)))
		wrpcap('test_udp_log.pcap', res)

	#Send and catch our own packet
	def test_send_and_catch(self):

		def send_packet():
			packet=IP(dst="0.0.0.0")/ICMP()/"TEST_LOAD"
			send(packet)

		def start_sniff(queue):
			res=sniff(lfilter = lambda x: x.haslayer(ICMP), iface=default_gateway, count=1)
			packetLoad = res[0].load
			if packetLoad == "TEST_LOAD":
				que.put(True)
			else:
				que.put(False)

		que = Queue.Queue()

		#init events
		e1 = threading.Event()
		e2 = threading.Event()

		# init threads
		t1 = threading.Thread(target=start_sniff, args=[que])
		t2 = threading.Thread(target=send_packet)

		# start threads
		t1.start()
		t2.start()

		e1.set() # initiate the first event

		# join threads to the main thread
		t1.join()
		t2.join()

		self.assertTrue(que.get())


suite = unittest.TestLoader().loadTestsFromTestCase(TestSequenceFunctions)
unittest.TextTestRunner(verbosity=2).run(suite)
