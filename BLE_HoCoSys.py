#!/usr/bin/env python3

import binascii
import sys
import time
import struct
import crcmod
from bluepy.btle import Scanner, DefaultDelegate, Peripheral, Service, Characteristic, UUID


#C O N T R O L   F R A M E S
ACKNOLEDGE	= 0x00	#Acknowledge
SET_NO_SEC_MODE 	= 0x04	#Set the ESP device security mode, Checksum:NO  Encryption:NO
SET_CHKSUM_ONLY 	= 0x14	#Set the ESP device security mode, Checksum:YES Encryption:NO
SET_ENC_ONLY		= 0x24	#Set the ESP device security mode, Checksum:NO  Encryption:YES
SET_CHKSYM_ENC		= 0x34	#Set the ESP device security mode, Checksum:YES Encryption:YES

SET_WIFI_MODE	= 0x08	#Set the op mode of WIFI
CONN_TO_AP	= 0x0C	#Connect ESP to AP
DISC_FROM_AP	= 0x10	#Disconnect ESP from AP0;63;50M0;63;50m
GET_WIFI_INFO	= 0x14	#Get information of the ESP WIFI Mode and status
DISC_SOFTAP	= 0x18	#Disconnect ESP from the SoftAP (in SoftAp Mode)
GET_VERSION	= 0x1C	#Get version information
DISC_BLE_DEV 	= 0x20	#Disconnect the BLE GATT link
GET_WIFI_LIST	= 0x24	#Get the WIFI slist

#D A T A   F R A M E S
SND_NEG_DATA =		0x01	#Send the negotiation Data
SND_BSSID_STA =		0x05	#Send the BSSID for STA mode
SND_SSID_STA =		0x09	#Send the SSID for STA mode
SND_PWD_STA =		0x0D	#Send the password for STA mode
SND_SSID_SOFTAP =	0x11	#Send the SSID for SoftAP mode.
SND_PWD_SOFTAP =	0x15	#Send the password for SoftAPmode.
SET_MAX_CONN_SOFTAP =	0x19	#Set the maximum connection number for SoftAP mode.
SET_AUTH_SOFTAP =	0x1D	#Set the authentication mode for SoftAP mode.
SET_NUM_CHN_SOFTAP =	0x21	#Set the number of channels for SoftAP mode.
SND_USERNAME =		0x25	#Username
CA_CERT =		0x29	#CA Certification
CLIENT_CERT =		0x2D	#Client Certification
SERVER_CERT =		0x31	#Server Certification
CLIENT_PRIV_KEY =	0x35	#Client Private Key
SERVER_PRIV_KEY	=	0x39	#Server Private Key
WI_CONN_REPORT =	0x3D	#Wi-Fi Connection State Report
SND_VERSION =		0x41	#Version
WIFI_LIST =		0x45	#Wi-Fi List
REPORT_ERRO =		0x49	#Report Error
CUSTOM_DATA =		0x4D	#Custom Data
SET_MAX_RECON_TIME =	0x51	#Set the maximum Wi-Fi reconnecting time.
SET_WIFI_END_RSN =	0x55	#Set the Wi-Fi connection end reason.
SET_RSSI_WIFI_CON =	0x59	#Set the RSSI at Wi-Fi connection end.


#F R A M E   C O N T R O L
#COMMAND                BIT
NOT_ENCRYPTED =		0x00 # 00000000 : Not encrypted, no checksum
ENCRYPTED = 		0x01 # 00000001 : Encreypted, no checksum
CHKSUM =		0x02 # 00000010 : Checksum, not encryted
ENC_CHKSUM =		0x03 # 00000011 : encryted and checksum
ESP_T0_MOB =	 	0x04 # 000001xx : from ESP --> MOBILE. / 000000xx Means from ESP <-- MOBILE
ACK_REQ =		0x08 # 00000xxx : not required to reply to an ACK. / 00001xxx: ACK is required
FRAGMENTS =		0x10 # 0001xxxx: there is subsequent data fragment for this frame. /0000xxxx: no subsequent data fragment
# 0x10~0x80 		Reserved

seqCtr = 0

# Peripheral device MAC address
PERIPHERAL_MAC = "f4:12:fa:88:20:ce"

# Service UUID
SERVICE_UUID = UUID(0xffff)

CHAR_UUID_W = UUID(0xff01)
CHAR_UUID_R = UUID(0xff02)

CHAR_W_HDL = 42
CHAR_R_HDL = 44

class Counter:
	count = -1

	def __init__(self):
		Counter.count += 1

	def get_count(self):
		return Counter.count

class MyDelegate(DefaultDelegate):
	def __init__(self,params=False):
		DefaultDelegate.__init__(self)


	def handleDiscovery(self, dev, isNewDev, isNewData):
		print("Scanning BTLE devices")
		if isNewDev:
			print("Discovered device", dev.addr)
		elif isNewData:
			print("Received new data from", dev.addr)

	def handleNotification(self, cHandle, data):
		print("Handling notification...")
		print("Received notification from handle %d: %s" % (cHandle, data))
		print("Notification from Handle:0x",format(cHandle,'02x'))
		print("Value: ",data)


def Get_peripherals_info():
	device = Peripheral()
	try:
	#Get BLE services
		print("Getting Services")
		services = device.getServices()
		num_services = len(services)
		print("Services found:%d"%(num_services))
		for index, srv in enumerate(services,start=1):
			print("Service: %d"%(index))
			print("service.uuid:",srv.uuid)
			print("service.peripheral.addr",srv.peripheral.addr)

		#Retrieve Characteristics
		characteristics = device.getCharacteristics()
		print("%d characteristics found"%(len(characteristics)))
		for charact in characteristics:
			print("GetHandle",charact.getHandle())
			print("characteristics.uuid",charact.uuid)
			print("characteristics.peripheral.addrType",charact.peripheral.addrType)
			print("characteristics.properties",charact.properties)
		device.disconnect()

	except Exception as e:
		print(f"error:{e}:",e)
		exit()


def connect_2_peripheral(address):
	device = Peripheral()
	try:
		print("Connecting to peripheral:%s"%(address))
		device.connect(PERIPHERAL_MAC)
		print("Peripheral:",address,"connection succeed!")
	except Exception as  e:
		print(f"error:{e}:",e)
		exit()
	return device

def disconnect_from_peripheral(device):
	print("Disconecting...")
	device.disconnect()
	print("Device disconnected")


def scan_dev(time = 1.0):
	scanner = Scanner().withDelegate(MyDelegate())
	devices = scanner.scan(timeout=time)
	print("Scanning complet")
	print("%d devices found"%(len(devices)))

	for index, dev in enumerate(devices, start=1):
		print ("[%i]Device addr:%s, Type:%s, RSSI=%d dB" %(index,dev.addr, dev.addrType, dev.rssi))
		for (adtype, desc, value) in dev.getScanData():
			print ("%s = %s",desc,value)

def get_characteristics_ByUUID(peripheral,Serv_UUID):
	"""Get characteristics by UUID"""
	services = peripheral.getServiceByUUID(Serv_UUID)
	Characteristics = services.getCharacteristics()
	for characteristic in Characteristics:
		print("characteristic>",Characteristics)

def get_characteristics(peripheral):
	"""Get characteristics"""
	services = peripheral.getServices()
	print("Num of Services:",len(services))
	for serv in services:
		print("Service>",serv)
		characteristics = serv.getCharacteristics()
		for charact in characteristics:
			print("characteristic>",charact)


def get_services(device):
	print("Getting Services...")
	Services = device.getServices()
	for service in Services:
		print("Service>",service)
	return  Services

def checksum(data):
	crc16 = crcmod.predefined.Crc('crc-16-genibus')
	crc16.update(data)
	crc=bytearray(2)
	print("Data subject to CRC:",data)
	crc = crc16.digest()
	print("CRC:",crc)
	return crc


def send_data(peripheral, frm_type,frm_ctrl,data=0x00):
	"""Send serial data to the peripheral"""
	print("Send serial data to the peripheral")
	CRC = bytearray(2)
	data_lenght = 0
	seq_Num = Counter()
	withResponse=True
	if (data != 0):
		data_lenght = len(data)
		print("data_lenght:",data_lenght)
		data_to_send = bytearray(data_lenght+6)
		data_to_send[0] = frm_type
		data_to_send[1] = frm_ctrl
		data_to_send[2] =  seq_Num.count
		data_to_send[3] = data_lenght
		for index, byte in enumerate(data,start=0):
			#print("index:",index)
			data_to_send[4+index] = data[index]
	else:
		data_to_send = bytearray(6)
		data_to_send[0] = frm_type
		data_to_send[1] = frm_ctrl
		data_to_send[2] = seq_Num.count
		data_to_send[3] = 0x00
		data_to_send[4] = 0x00
		data_to_send[5] = 0x00

	print("Conf Data Subject to CRC:",data_to_send[2:4+data_lenght])
	CRC=checksum(data_to_send[2:4+data_lenght])

	data_to_send[-1] = CRC[0]
	data_to_send[-2] = CRC[1]

	print("Data to send:",bytearray(data_to_send))

	srv = peripheral.getServiceByUUID(SERVICE_UUID)
	charact = srv.getCharacteristics(CHAR_UUID_W)[0]
	charact.write(data_to_send,withResponse)

def send_data_fix(peripheral, data, withResponse):
	"""Send serial data to the peripheral"""
	print("Send serial data to the peripheral")

	print("Data to send:",data)
	formated_data_to_send = bytes.fromhex(data)
	srv = peripheral.getServiceByUUID(SERVICE_UUID)
	charact = srv.getCharacteristics(CHAR_UUID_W)[0]
	charact.write(formated_data_to_send,withResponse)

def crc_test(data):
	"""Send serial data to the peripheral"""
	print("Send serial data to the peripheral")
	CRC = 0x0000
	data_lenght = 0
	seq_Num = Counter()
	withResponse=True
	if (data != 0):
		data_lenght = len(data)
		print("data_lenght:",data_lenght)
		data_to_send = bytearray(data_lenght+6)
		data_to_send[0] = CUSTOM_DATA
		data_to_send[1] = NOT_ENCRYPTED
		data_to_send[2] =  seq_Num.count
		data_to_send[3] = data_lenght
		for index, byte in enumerate(data,start=0):
			#print("index:",index)
			data_to_send[index+4] = data[index]
	else:
		data_to_send = bytearray(6)
		data_to_send[0] = CUSTOM_DATA
		data_to_send[1] = NOT_ENCRYPTED
		data_to_send[2] =  seq_Num.count
		data_to_send[3] = 0x00
		data_to_send[4] = 0x00
		data_to_send[5] = 0x00

	print("Data Subject to CRC:",data_to_send[2:4+data_lenght])
	checksum(data_to_send[2:4+data_lenght])

	print("Data to send:",bytearray(data_to_send))


def main():

	loop = True

	HoCoSys_peripheral = connect_2_peripheral(PERIPHERAL_MAC)
	HoCoSys_peripheral.setDelegate(MyDelegate(HoCoSys_peripheral))


	data2 = '1C0001000000'
	data1 = '4D00000241420000'
	data =  [0x41,0x42,0x43,0x44,0x45]
	data3 =  bytes(b'123dsiuhsdfhsdjflds4567890')


	send_data(HoCoSys_peripheral,SET_CHKSUM_ONLY,NOT_ENCRYPTED)
	send_data(HoCoSys_peripheral,CUSTOM_DATA,NOT_ENCRYPTED,data3)
	send_data(HoCoSys_peripheral,GET_VERSION,NOT_ENCRYPTED)

#	send_data_fix(HoCoSys_peripheral,data2,True)

	serv = HoCoSys_peripheral.getServiceByUUID(SERVICE_UUID)
	R_char = serv.getCharacteristics(CHAR_UUID_R)[0]

	val = R_char.read()
	print("val:",val)

	while loop:

		while True:
			if HoCoSys_peripheral.waitForNotifications(1.0):
				print("Waiting for notification..")
				continue
			else:
				print("Notification received")
				break

		usrInput = input("Enter text to send:")

		if(usrInput == ".exit"):
			loop = False

		elif (usrInput == ".scan"):
			scan_dev(5.0)

		elif (usrInput == ".version"):
			send_data(HoCoSys_peripheral,GET_VERSION,NOT_ENCRYPTED)

		else:
			data = bytes(usrInput,'utf-8')
			send_data(HoCoSys_peripheral,CUSTOM_DATA,CHKSUM,data)
			'''crc_test(data)'''

	disconnect_from_peripheral(HoCoSys_peripheral)


#BlueFiPeripheral =  Peripheral(deviceAddress="f4:12:fa:88:20:ce",addrType=ADDR_TYPE_PUBLIC, iface=0)
#scanner = bluepy.btle.Scanner()
#devices = scanner.scan(timeout=10)
#print ("Devices:",devices)

#dev = bluepy.btle.Peripheral(devices[0].addr)

#characteristic = dev.getCharacteristics(uuid="0000ffff-0000-1000-8000-00805f9b34fb")[0]
#data = characteristic.read()
#print("Read data:", data)
#characteristic.write(b"hello world")#python 3.11


if __name__ == "__main__":
	main()
