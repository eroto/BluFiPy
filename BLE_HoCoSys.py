#!/home/enrique/venv/bin/python3
import binascii
import sys
import time
import struct
import crcmod
import asyncio
#from /home/enrique/Projects/py_env/bluepy.btle import Scanner, DefaultDelegate, Peripheral, Service, Characteristic, UUID
from bluepy3.btle import Scanner, DefaultDelegate, Peripheral, Service, Characteristic, UUID
from BluFiDef import *


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
	print(f"Starting connection to peripheral:{address}")
	
	try:
		device = Peripheral()
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

def set_sec_mode(peripheral, BluFiObj):
	"""Send security mode data to the peripheral"""
	print("Send security mode")
	data_lenght = 0
	seq_Num = Counter()
	withResponse=True

	data_to_send = bytearray(4)
	data_to_send[0] = BluFiObj.Ctrl_Data
	data_to_send[1] = BluFiObj.FrmCtrl
	data_to_send[2] = seq_Num.count
	data_to_send[3] = 0x00
	print("Sec. Mode to send:",bytearray(data_to_send))

	srv = peripheral.getServiceByUUID(SERVICE_UUID)
	charact = srv.getCharacteristics(CHAR_UUID_W)[0]
	charact.write(data_to_send,withResponse)


def send_data(peripheral, BluFiObj, data = 0x00):
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
		data_to_send[0] = BluFiObj.Ctrl_Data
		data_to_send[1] = BluFiObj.FrmCtrl
		data_to_send[2] = seq_Num.count
		data_to_send[3] = data_lenght
		for index, byte in enumerate(data,start=0):
			#print("index:",index)
			data_to_send[4+index] = data[index]
		print("Conf Data Subject to CRC:",data_to_send[2:(4+data_lenght)])
		CRC=checksum(data_to_send[2:(4+data_lenght)])

	else:
		data_to_send = bytearray(6)
		data_to_send[0] = BluFiObj.Ctrl_Data
		data_to_send[1] = BluFiObj.FrmCtrl
		data_to_send[2] = seq_Num.count
		data_to_send[3] = 0x00
		data_to_send[4] = 0x00
		data_to_send[5] = 0x00
		print("Conf Data Subject to CRC:",data_to_send[2:4])
		CRC=checksum(data_to_send[2:(4+data_lenght)])
	
	data_to_send[-1] = CRC[0]
	data_to_send[-2] = CRC[1]

	print("Full Data to send:",bytearray(data_to_send))

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
	
	#Write data to the characteristic with response
	charact.write(formated_data_to_send,withResponse)

	#wait for response
	'''
	if withResponse:
		print("Waiting for response...")
		while True:
			if peripheral.waitForNotifications(1.0):
				print("Waiting for notification..")
				continue
			else:
				print("Notification received")
				break
				'''

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
	BlueFiObj = BluFiDef()

	HoCoSys_peripheral = connect_2_peripheral(PERIPHERAL_MAC)
	HoCoSys_peripheral.setDelegate(MyDelegate(HoCoSys_peripheral))


	data0 = '14000000'
	data1 = '4D00000241420000'
	data2 = '1C0001000000'
	data =  [0x41,0x42,0x43,0x44,0x45]
	data3 =  bytes(b'HOLA')

	#print("Send Data fix")
	#send_data_fix(HoCoSys_peripheral,data0,True)

	print("SET_CHKSUM_ONLY, NOT_ENCRYPTED")
	BlueFiObj.SetMsgValues(SET_CHKSUM_ONLY, NOT_ENCRYPTED)
	#BlueFiObj.Ctrl_Data = SET_CHKSUM_ONLY
	#BlueFiObj.FrmCtrl = NOT_ENCRYPTED
	set_sec_mode(HoCoSys_peripheral,BlueFiObj)

	#BlueFiObj.Ctrl_Data = BluFiDef.CUSTOM_DATA
	#BlueFiObj.FrmCtrl = BluFiDef.NOT_ENCRYPTED
	print("CUSTOM_DATA + CHKSUM")
	BlueFiObj.SetMsgValues(CUSTOM_DATA, CHKSUM)
	send_data(HoCoSys_peripheral,BlueFiObj,data3) 

	print("GET_VERSION")
	BlueFiObj.Ctrl_Data = GET_VERSION
	send_data(HoCoSys_peripheral,BlueFiObj)

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
			BlueFiObj.Ctrl_Data = GET_VERSION
			BlueFiObj.FrmCtrl = NOT_ENCRYPTED
			send_data(HoCoSys_peripheral,BlueFiObj)

		else:
			data = bytes(usrInput,'utf-8')
			BlueFiObj.Ctrl_Data = CUSTOM_DATA
			BlueFiObj.FrmCtrl = CHKSUM
			send_data(HoCoSys_peripheral,BlueFiObj,data)
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
