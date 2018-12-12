#!/usr/bin/env python
from scapy.all import *
from scapy_http import http
import os
import requests
import socket
import urllib
import json



print "Sniffing..."

def process_tcp_packet(packet):
	if not packet.haslayer(http.HTTPRequest):
		return
	http_layer = packet.getlayer(http.HTTPRequest)
	ip_layer = packet.getlayer(IP)
	#ignores all requests that are not http requests, the above lines can be changed to include different type of traffic
	a = ('{1[Host]}'.format(ip_layer.fields, http_layer.fields))
	b =(socket.gethostbyname(a))
	print (a)
	print (b)
	#"a" is the url that is extracted from the traffic, "b" is the ip address extracted from traffic

	headers = {
  	"Accept-Encoding": "gzip, deflate",
  	"User-Agent" : "gzip,  My Python requests library example client or username"
  	}
	params = {'apikey': 'API-KEY-HERE', 'resource':a}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
	json_response = response.json()
	x = (json_response['positives'])
	y = (json_response['total'])
	print(str(x) + " Virus engines detected it malicious out of " + str(y))
	#request is sent to virustotal, x is the number of virus engines that have detected the particular url as a virus, y is the total amount of virus engines that have scanned the particular url
	#for more control, an if statement can be added on "x" e.g. if x > 1, send to end-point machine

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	host = '10.40.84.176'
	#the host ip is the ip address of the end-point machine
	port = 4444
	s.connect((host, port))
	s.send(b)
	#the ip address "b" is sent to a netcat listener on the end-point machine. the end-point machine must be listening on port 4444
	print (b + " has been sent to socket")
 
sniff(filter='tcp', prn=process_tcp_packet, iface="eno1")
