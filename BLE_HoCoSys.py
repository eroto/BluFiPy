#!/home/enrique/venv/bin/python3
#{{ ESP Blufi implementation }}
#Copyright (C) {{ 2024 }}  {{ Enrique Rodriguez Toscano }}

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binascii
import sys
import time
import struct
import crcmod
import asyncio
from bluepy3.btle import Scanner, DefaultDelegate, Peripheral, Service, Characteristic, UUID, ADDR_TYPE_PUBLIC
from BluFiDef import *
import argparse
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import os


# Peripheral device MAC address
PERIPHERAL_MAC = "F4:12:FA:88:20:CE"

SSID1 = "IZZI-9AED"
SSID1_PWD = "hn2637ay"

SSID2 = "TP-Link_8ED8"
SSID2_PWD = "E599*58208"

# Service UUID
SERVICE_UUID = UUID(0xffff)

CHAR_UUID_W = UUID(0xff01)
CHAR_UUID_R = UUID(0xff02)

CHAR_W_HDL = 42
CHAR_R_HDL = 44

class MyDelegate(DefaultDelegate):
	def __init__(self, ack_tracker: AckTracker):
		super().__init__()
		self.ack_tracker = ack_tracker
		self.fragment_buffer = b""
		self.expected_len = None
		self.full_payload_ready = False
		
	def handleDiscovery(self, dev, isNewDev, isNewData):
		print("Scanning BTLE devices")
		if isNewDev:
			print("Discovered device", dev.addr)
		elif isNewData:
			print("Received new data from", dev.addr)

	def handleNotification(self, cHandle, data):
		print("Delegate: Notification received")
		ack_seq = parse_ack_frame(data)
		if ack_seq is not None:
			print(f"Delegate: ACK received for sequence {ack_seq}")
			self.ack_tracker.confirm_ack(ack_seq)
		#else:
			#print("Delegate: No ACK frame detected, processing data...")

		frame_type = data[0]
		frame_Ctrl = data[1]
		seq_num = data[2]
		data_len = data[3]
		payload = data[4:4+data_len]

		print(f"frame_type:{hex(frame_type)} frame Ctrl:{hex(frame_Ctrl)}")
		print(f"RX_seq_num:{seq_num} Data lenght:{data_len}")
		#Global_Seq_Num.inc_count()
		#print("Fragment:",' '.join (f'{b:02x}' for b in data))
		#print(f"fragment: {binascii.hexlify(data).decode()}")
		#check if bit4 of frame_Ctrl is set, if so, it means there is a subsequent data fragment
		if frame_Ctrl & FRAGMENTS:
			#print(f"Fragment Frame: {True}")
			total_len = int.from_bytes(payload[0:2], byteorder='little')
			print(f"Total Lenght of data:{total_len}")
			if self.expected_len is None:
				#print(f"Expected length is None, setting it now: {total_len} ")
				#self.expected_len = total_len
				self.fragment_buffer = payload[2:]  # Start with the first fragment
				print(f"1st Fragment:",' '.join (f'{b:02x}' for b in data))
				#print(f"First fragment received: {binascii.hexlify(self.fragment_buffer).decode()}")
			else:
				#print(f"Subsequent data fragment: {True}")
				self.fragment_buffer += payload[2:]  # Append subsequent fragments
				print(f"subsequent Fragment:",' '.join (f'{b:02x}' for b in payload))
			
				if len(self.fragment_buffer) >= self.expected_len:
					self.full_payload_ready = True
					#print(f"Full Payload received (hex): {binascii.hexlify(self.fragment_buffer).decode()}")
					print(f"Full Payload received: {self.fragment_buffer}")
					self.expected_len = None  # Reset for next message
					self.fragment_buffer = b""  # Clear buffer
		else:
			#print(f"Fragment Frame: {False}")
			#Check if this is the last fragment from previoss message
			if (len(self.fragment_buffer) + data_len) == self.expected_len:
				#print("Last fragment received")
				self.fragment_buffer += payload
				print(f"Shall not be reached (❌) Full Payload Received (hex): {binascii.hexlify(self.fragment_buffer).decode()}")
				#print(f"Full Payload: {self.fragment_buffer}")
				self.full_payload_ready = True
				self.expected_len = None
			else:
				print("Single frame received, no fragments")
				# This is a single frame without fragments
				#print(f"Single Frame Payload (hex): {binascii.hexlify(payload).decode()}")
				print(f"Single Frame Payload: {payload}")
				# Store the payload directly
				self.fragment_buffer = b""  # Clear buffer for single frame
				self.expected_len = None  # Reset expected length
				# If the payload is not empty, set it as the full payload
				if payload:
					#print("Storing single frame payload")
					# Store the payload as the full payload
					# This is a single frame without fragments
					#lprint(f"Single Frame Payload (hex): {binascii.hexlify(payload).decode()}")
					#print(f"Single Frame Payload: {payload}")
					fragment_buffer = payload
					self.full_payload_ready = True
					self.expected_len = data_len				
		'''
		if frame_type == 0x3D:
			print(f"Raw Payload (hex): {binascii.hexlify(data[4:4+data_len]).decode()}")
			print(f"Pay Load:{data[4:4+data_len]}")
		'''


def GenDHParams():
	# Generate DH parameters (generator=2, key size=512 bits)
	parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
	# Generate private key
	private_key = parameters.generate_private_key()

	# Export private key to PEM
	private_key_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
		)

	# Export parameters to PEM
	parameters_pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
		)

	# Export public key in DER format (to send to ESP32)
	public_key_bytes = private_key.public_key().public_bytes(
		encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

    # Return all key material needed for DH negotiation
	print("Generated DH Parameters")
	return{
		'parameters': parameters,
		'private_key': private_key,
		'private_key_pem': private_key_pem,
		'parameters_pem': parameters_pem,
        'public_key_bytes': public_key_bytes

	}
	
def Prepare_WiFi_Data(wifi_data: str) -> bytes:

	"""
	Prepare wifi_data for sending to the ESP32.
	Returns a byte array withwifi_data.
	"""
	if not wifi_data:
		raise ValueError("wifi_data cannot be empty")
	
	# Convert wifi_data to bytes
	data_bytes = wifi_data.encode('utf-8')

	if len(wifi_data) > 255:
		raise ValueError("Data too long (max 255 bytes)")
		
	print(f"Prepared data ({len(data_bytes)} bytes):", data_bytes)
	
	return data_bytes

def ComputeSharedKey(private_key, esp_payload):
	"""
    Takes the DH_Param dictionary and ESP32's raw public key payload.
    Computes the shared secret and derives the AES encryption key.
    """
	try:
		peer_pub_key = load_der_public_key(esp_payload, backend=default_backend())

		#Compute shared DH secret
		shared_secret = DH_Param['private_key'].exchange(peer_pub_key)
	
		# Derive the AES key from the shared secret
		aes_key = HKDF(algorithm = hashes.SHA256(),lenght = 16, salt=None, info=b'blufi-AES-Key', backend=default_backend()).derive(shared_secret)
		print("Shared AES key derived successfully")
		return aes_key
	except Exception as e:
		print(f"Fail to process ESP Pub Key: {e}")
		return None



def save_dh_keys(parameters, private_key, public_key_bytes, folder="dh_keys"):
	os.makedirs(folder, exist_ok=True)

	# Save public key (DER)
	with open(os.path.join(folder, "dh_public_key.der"), "wb") as pub_file:
		pub_file.write(public_key_bytes)
		
	# Save DH parameters (p, g) in PEM
	param_bytes = parameters.parameter_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.ParameterFormat.PKCS3
		)
	with open(os.path.join(folder, "dh_parameters.pem"), "wb") as param_file:
		param_file.write(param_bytes)


	# Save private key (PEM, PCKCS8 format)
	private_bytes = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
		)
	with open(os.path.join(folder, "dh_private_key.pem"), "wb") as priv_file:
		priv_file.write(private_bytes)

	print("✅ DH parameters, public & private keys saved to folder:", folder)

def load_dh_keys(folder="dh_keys"):
	#load Dh Parameters
	with open(os.path.join(folder, "dh_parameters.pem"), "rb") as param_file:
		params = serialization.load_pem_parameters(param_file.read(), backend=default_backend())

	
	# Load private key
	with open(os.path.join(folder, "dh_private_key.pem"), "rb") as priv_file:
		private_key = serialization.load_pem_private_key(priv_file.read(),password=None,backend=default_backend())
		#Ger parameters from private key
		#params = private_key.parameters()

    	# Regenerate public key from private key
		public_key_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	
	print("✅ DH keys loaded from folder:", folder)
	
	return {
		'private_key': private_key,
		'public_key_bytes': public_key_bytes,
		'parameters': params
		}


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


async def connect_2_peripheral(address, ack_tracker: AckTracker = AckTracker()):
	print(f"Starting connection to peripheral:{address}")
	
	try:
		device = Peripheral()
		delegate = MyDelegate(ack_tracker)
		device.setDelegate(delegate)
		print("Connecting to peripheral:%s"%(address))
		device.connect(address,addrType=ADDR_TYPE_PUBLIC,iface=0)
		print("Peripheral:",address,"connection succeed!")
	except Exception as  e:
		print(f"error:{e}:",e)
		exit()
	return device

def disconnect_from_peripheral(device):
	print("Disconecting...")
	device.disconnect()
	print("Device disconnected")


async def scan_dev():
	scanner = Scanner(0).withDelegate(delegate())
	devices = scanner.scan(time)
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

def ProcessESP_DHKey(DH_Param, esp_payload):
	"""
    Takes the DH_Param dictionary and ESP32's raw public key payload.
    Computes the shared secret and derives the AES encryption key.
    """
	try:
		# Load the ESP32 public key from the payload
		esp_public_key = load_der_public_key(esp_payload, backend=default_backend())
		# Compute the shared secret using the private key and ESP32's public key
		shared_secret = DH_Param['private_key'].exchange(esp_public_key)
		print("Shared secret computed successfully")
		# Derive the AES key from the shared secret
		aes_key = shared_secret[:16]  # Use the first 16 bytes for AES-128
		print("AES key derived successfully")
		return aes_key
	except Exception as e:
		print(f"Error processing ESP32 public key: {e}")
		return None


def checksum(data):
	crc16 = crcmod.predefined.Crc('crc-16-genibus')
	crc16.update(data)
	crc=bytearray(CRC_LENGTH)
	crc = crc16.digest()
	return crc

async def set_sec_mode(peripheral, BluFiObj):
	"""Send security mode data to the peripheral"""
	print("Send security mode")
	data_lenght = 0
	#Global_Seq_Num = Counter()
	withResponse=True

	#check for Ctrl_Data if it's different than SET_NO_SEC_MODE or SET_CHKSUM_ONLY
	#or SET_ENC_ONLY or SET_CHKSYM_ENC
	if ((BluFiObj.Ctrl_Data != SET_NO_SEC_MODE) and
		(BluFiObj.Ctrl_Data != SET_CHKSUM_ONLY) and
		(BluFiObj.Ctrl_Data != SET_ENC_ONLY) and
		(BluFiObj.Ctrl_Data != SET_CHKSYM_ENC)):
		print("Ctrl_Data is not valid")
		return

	data_to_send = bytearray(4)
	data_to_send[0] = BluFiObj.Ctrl_Data
	data_to_send[1] = BluFiObj.FrmCtrl
	data_to_send[2] = Global_Seq_Num.get_count()
	print(f"Tx Seq count: {data_to_send[2]}")
	data_to_send[3] = 0x00
	#print(f"Sec. Mode to send:{binascii.hexlify(data_to_send).decode()}")

	await Transmit_data(peripheral,data_to_send,withResponse)
	await Peripheral_Response(peripheral, peripheral.delegate)

async def Connect2AP(peripheral, BluFiObj):
	"""SSI and Password is sent, send Connection request to ESP32"""
	print("Send Connect AP request")
	data_lenght = 0
	#Global_Seq_Num = Counter()
	withResponse=True

	data_to_send = bytearray(6)
	data_to_send[0] = BluFiObj.Ctrl_Data
	data_to_send[1] = BluFiObj.FrmCtrl
	data_to_send[2] = Global_Seq_Num.get_count()
	data_to_send[3] = 0x00 # No data to send, just the request
	CRC = checksum(data_to_send[2:4])
	print("Sec. Mode to send:",bytearray(data_to_send))
	data_to_send[-1] = CRC[0]
	data_to_send[-2] = CRC[1]
	#await crc_test(data_to_send[2:4])

	await Transmit_data(peripheral,data_to_send,withResponse)
	await Peripheral_Response(peripheral, peripheral.delegate)


async def ack_monitor_loop(ack_tracker: AckTracker, resend_callback, interval: float = 2.0, retry_limit: int = 3):
    retry_count = {}  # seq_num: retries attempted

    while True:
        await asyncio.sleep(interval)
        missing_acks = ack_tracker.get_missing_acks(timeout=interval)

        for seq in missing_acks:
            count = retry_count.get(seq, 0)
            if count < retry_limit:
                print(f"🔁 Resending frame #{seq} — ACK missing (retry {count + 1}/{retry_limit})")
                await resend_callback(seq)
                retry_count[seq] = count + 1
            else:
                print(f"❌ Max retries reached for frame #{seq}, giving up")


async def resend_frame(seq_num: int):
    data = sent_frames.get(seq_num.count)
    if data:
        await send_data(peripheral, BluFiObj, data=data, wait_for_response=False)
    else:
        print(f"⚠️ No frame cached for seq #{seq_num.count}")


async def send_data(peripheral, BluFiObj, data = "", wait_for_response=True):
	"""Send serial data to the peripheral"""
	#print("Send serial data to the peripheral")
	CRC = bytearray(2)
	#data_lenght = 0
	
	withResponse=True
	
	# Normalize data to bytes
	if isinstance(data, int):
		data_bytes = bytes([data])
	elif isinstance(data, str):
		data_bytes = data.encode()  # UTF-8 encoding
	elif isinstance(data, (bytes, bytearray)):
		data_bytes = bytes(data)
	else:
		raise TypeError("Data must be int, str, bytes, or bytearray")

	data_lenght = len(data_bytes)
	#Global_Seq_Num = Counter()

	if (data_lenght > 0 and data_lenght <= MAX_CHUNK_SIZE):
		#reserve 4 bytes for Frame Ctrl + n bytes of data + 2 bytes CRC
		data_to_send = bytearray(4) + data_bytes + bytearray(2)
		data_to_send[0] = BluFiObj.Ctrl_Data
		data_to_send[1] = BluFiObj.FrmCtrl
		data_to_send[2] = Global_Seq_Num.get_count()
		print(f"Seq count: {data_to_send[2]}")
		data_to_send[3] = data_lenght #TODO falta sumar 2 bytes for chuck del tamaño total de datos
		#print("Data to send:",' '.join(f'{b:02x}' for b in data_to_send))
		#print("Conf Data Subject to CRC:",data_to_send[2:(4+data_lenght)])
		CRC = checksum(data_to_send[2:(4+data_lenght)])
		#await crc_test(data_to_send[2:4+data_lenght])

	elif (data_lenght > MAX_CHUNK_SIZE):
		#data is larger to MAX_CHUNK_SIZE, so we need to split it into chunks of MAX_CHUNK_SIZE bytes
		print(f"Data length ({data_lenght}) exceeds MAX_CHUNK_SIZE ({MAX_CHUNK_SIZE}), splitting into chunks")
		chunks = [data_bytes[i:i + MAX_CHUNK_SIZE] for i in range(0, data_lenght, MAX_CHUNK_SIZE)]
		#send the chunks in for loop
		index = 0
		for chunk in chunks:
			chunk_length = len(chunk)
			print(f"Chunk length: {chunk_length} Chunk data: {chunk.hex()}")
			
			if chunk_length < MAX_CHUNK_SIZE:
				data_to_send = bytearray(4)+chunk+ bytearray(2)
				data_to_send[0] = BluFiObj.Ctrl_Data
				data_to_send[1] = BluFiObj.FrmCtrl & ~FRAGMENTS
				data_to_send[3] = chunk_length
				d_idx = 4
			else:
				data_to_send = bytearray(4)+bytearray(2)+chunk+ bytearray(2)
				data_to_send[0] = BluFiObj.Ctrl_Data
				data_to_send[1] = BluFiObj.FrmCtrl|FRAGMENTS
				data_to_send[3] = chunk_length+2
				data_to_send[4] = data_lenght - (chunk_length * index) # Total data length is 157 - chunk_length
				data_to_send[5] = 0
				d_idx = 6
			data_to_send[2] = Global_Seq_Num.get_count()
			print(f"Seq count: {data_to_send[2]}")
			#data_to_send[3] = chunk_length+2
			#Total data lenght
			#if (data_lenght - (chunk_length * index)) > MAX_CHUNK_SIZE:
				#data_to_send[4] = data_lenght - (chunk_length * index) # Total data length is 157 - chunk_length
				#data_to_send[5] = 0
				#d_idx = 6
			#else:
				#d_idx = 4
			index += 1
			#print("Data to send:",' '.join(f'{b:02x}' for b in data_to_send))
			print("Conf Data Subject to CRC:",binascii.hexlify(data_to_send[2:(d_idx+chunk_length)]).decode())
			CRC = checksum(data_to_send[2:(d_idx+chunk_length)])
			#await crc_test(data_to_send[2:5+chunk_length])
			data_to_send[-1] = CRC[0]
			data_to_send[-2] = CRC[1]
			# Register this frame in ack_tracker
			ack_tracker.mark_sent(Global_Seq_Num.get_count())
			#print(f"Seq count: {Global_Seq_Num.get_count()}")

			await Transmit_data(peripheral,data_to_send,withResponse, sent_frames=sent_frames)
			#print("Data transmitted:",' '.join (f'{b:02x}' for b in data_to_send))

			if wait_for_response:
				#asyncio wait for the response from the handlenotification
				await Peripheral_Response(peripheral, peripheral.delegate)
		return  # Exit after sending all chunks



	else: # Data is empty or no data to send
		#fill the data_to_send with 0x00 using lambda
		#data_to_send = bytearray(map(lambda x: 0x00, range(6)))
		data_to_send = bytearray(6)  # 4 header + 0 data + 2 CRC
		data_to_send[0] = BluFiObj.Ctrl_Data
		data_to_send[1] = BluFiObj.FrmCtrl
		data_to_send[2] = Global_Seq_Num.get_count()
		data_to_send[3] = 0x00 # No data to send, just the request
		#print("Data to send:",' '.join(f'{b:02x}' for b in data_to_send))
		#print("Conf Data Subject to CRC:",data_to_send[2:4])
		CRC=checksum(data_to_send[2:4])
		#await crc_test(data_to_send[2:4])
	
	data_to_send[-1] = CRC[0]
	data_to_send[-2] = CRC[1]
	# Register this frame in ack_tracker
	ack_tracker.mark_sent(Global_Seq_Num.get_count())

	await Transmit_data(peripheral,data_to_send,withResponse, sent_frames=sent_frames)
	print("Data transmitted:",' '.join (f'{b:02x}' for b in data_to_send))

	if wait_for_response:
		#asyncio wait for the response from the handlenotification
		await Peripheral_Response(peripheral, peripheral.delegate)

async def Transmit_data(peripheral, data, response = False, sent_frames=None):
	srv = peripheral.getServiceByUUID(SERVICE_UUID)
	charact = srv.getCharacteristics(CHAR_UUID_W)[0]
	charact.write(data,response)
	print("Data transmitted:",' '.join (f'{b:02x}' for b in data))
	#print(f"Data sent to peripheral: {binascii.hexlify(data).decode()}")
	Global_Seq_Num.inc_count()  # Increment sequence number for next frame

	if sent_frames is not None and len(data) >= 4:
		# Store the sent frame for potential resending
		seq_num = data[2]
		sent_frames[seq_num] = data
		#print(f"Frame #{seq_num} cached for potential resending")

async def crc_test(data):
	"""Prints CRC to be sent"""
	#print("CRC Test")
	CRC = 0x0000
	data_lenght = len(data)
	
	#print("data_lenght:",data_lenght)
	data_to_send = data

	print("Data Subject to CRC:",' '.join(f'{b:02x}' for b in data))
	CRC = checksum(data)

	print("CRC to send:", ' '.join(f'{b:02X}' for b in CRC))



async def Peripheral_Response(peripheral, delegate):
	"""Wait for the response from the peripheral"""
	print("Waiting for response...")
	timeout_ctr = 0
	result = False
	delegate.full_payload_ready = False

	# Wait for notification
	while timeout_ctr < MAX_TIMEOUTS:
		result = peripheral.waitForNotifications(NOTIFICATION_TIMEOUT)
		#print("Notification result:", result)
		if result is True:
			if delegate.full_payload_ready:
				full_data = delegate.fragment_buffer
				delegate.full_payload_ready = False
				delegate.fragment_buffer = b""  # Clear buffer after processing
				delegate.expected_len = None  # Reset expected length
				print("Full payload received:", ' '.join(f'{b:02x}' for b in full_data))
				return full_data
			else:
				print(f"Partial payload received, waiting more data... timeout_ctr: {timeout_ctr}")
				timeout_ctr += 1
				continue
		else:
			print("timeout waiting for notificatoin")
			timeout_ctr += 1
			print(f"Timeout counter: {timeout_ctr}")
	print("Time out!!, no response received from the peripheral")
	return None
		
		
			
async def GetPheripheralVersion(peripheral):
	"""Get the peripheral version"""
	print("Get peripheral version")
	BlueFiObj = BluFiDef()
	BlueFiObj.Ctrl_Data = GET_VERSION
	BlueFiObj.FrmCtrl = CHKSUM
	await send_data(peripheral, BlueFiObj, wait_for_response=True)

def parse_ack_frame(frame: bytes) -> int | None:
	"""
	Parses a BluFi ACK frame and returns the acknowledged sequence number.
	Returns None if frame is not an ACK.
	"""
	if len(frame) < 6:
		return None  # Too short to be valid
	
	frame_type = frame[0]
	frame_ctrl = frame[1]
	ack_seq = frame[4]
	data_len = frame[3]
	
	# Check if it's a control frame of subtype ACK
	if	frame_type == 0x00 and data_len == 0x01:
		print(f"✅ BluFi ACK received for sequence #{ack_seq}")
		return ack_seq
	
	return None

async def send_neg_data(peripheral, BlueFiObj):
	print(f"Start Negotiation Data, sending Pub Key to ESP32")
	BlueFiObj.Ctrl_Data = SND_NEG_DATA
	BlueFiObj.FrmCtrl = 0x1C#NOT_ENCRYPTED|CHKSUM
	#print PubKey in hex
	PubKey = DH_Param['public_key_bytes']
	len(PubKey) # Get the length of the public key
	#print the length of the public key
	#print(f"Public Key Length: {len(PubKey)} bytes")
	#print(f"Public Key (hex): {binascii.hexlify(PubKey).decode()}")
	await send_data(peripheral, BlueFiObj, PubKey, wait_for_response=False)



async def main():

	loop = True
	#delegate = MyDelegate()
	BlueFiObj = BluFiDef()
	HoCoSys_peripheral = await connect_2_peripheral(PERIPHERAL_MAC, ack_tracker)
	#HoCoSys_peripheral.setDelegate(delegate)

	asyncio.create_task(ack_monitor_loop(ack_tracker, resend_frame, interval=2.0, retry_limit=3))

	print("Configuring SET_CHKSUM_ONLY, NOT_ENCRYPTED")
	BlueFiObj.SetMsgValues(SET_CHKSUM_ONLY, NOT_ENCRYPTED)
	await set_sec_mode(HoCoSys_peripheral,BlueFiObj)

	print("Configuring NEGOTIATION DATA, NOT_ENCRYPTED")
	await send_neg_data(HoCoSys_peripheral, BlueFiObj)

	#Global_Seq_Num.inc_count()  # Increment sequence number for the next frame

	'''
	print("Configuring SET_WIFI_MODE, STA Mode")
	BlueFiObj.Ctrl_Data = SET_WIFI_MODE
	BlueFiObj.FrmCtrl = CHKSUM
	await send_data(HoCoSys_peripheral, BlueFiObj, 0x01, wait_for_response=False)
	
	print("Configuring WIFI SSID")
	BlueFiObj.Ctrl_Data = SND_SSID_STA
	BlueFiObj.FrmCtrl = CHKSUM
	await send_data(HoCoSys_peripheral, BlueFiObj, SSID1, wait_for_response=False)

	print("Configuring WIFI PWD")
	BlueFiObj.Ctrl_Data = SND_PWD_STA
	BlueFiObj.FrmCtrl = CHKSUM
	await send_data(HoCoSys_peripheral, BlueFiObj, SSID1_PWD, wait_for_response=False)

	print("Configuring Req. ESP32 CONN_TO_AP")
	BlueFiObj.Ctrl_Data = CONN_TO_AP
	BlueFiObj.FrmCtrl = CHKSUM
	await Connect2AP(HoCoSys_peripheral, BlueFiObj)
	'''
	

	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--version", action="store_true", help="Show version information")
	parser.add_argument("-w", "--wifi", action="store_true", help="Show Wi-Fi information")
	parser.add_argument("-l", "--list", action="store_true", help="Show Wi-Fi list")
	parser.add_argument("-s", "--scan", action="store_true", help="Scan for BLE devices")
	parser.add_argument("-x", "--exit", action="store_true", help="Exit the program")
	parser.add_argument("-c", "--command", action="store_true", help="Send command to the device")

	

	while loop:
		# Get user input in usrInput
		print("Enter command:")
		usrInput = input("> ")

		# pass the userInput to the parser
		args = parser.parse_args(usrInput.split())
		if args.version:
			await GetPheripheralVersion(HoCoSys_peripheral)
			continue
		if args.wifi:
			BlueFiObj.Ctrl_Data = GET_WIFI_INFO
			BlueFiObj.FrmCtrl = CHKSUM
			await send_data(HoCoSys_peripheral,BlueFiObj, wait_for_response=True)
			continue
		if args.list:
			BlueFiObj.Ctrl_Data = GET_WIFI_LIST
			BlueFiObj.FrmCtrl = CHKSUM
			await send_data(HoCoSys_peripheral,BlueFiObj,wait_for_response=True)
			continue
		if args.scan:
			await scan_dev()
			continue
		if args.command:
			print("Enter command to send to the device:")
			data = input("> ")
			if data:
				BlueFiObj.Ctrl_Data = CUSTOM_DATA
				BlueFiObj.FrmCtrl = CHKSUM
				await send_data(HoCoSys_peripheral, BlueFiObj, data,wait_for_response=True)
			else:
				print("No command entered")
			continue
		if args.exit:
			print("Exiting the program")
			loop = False
			continue
		# If no command is entered, show the help
		if not usrInput:
			parser.print_help()
			continue
		else:
			print("Unknown command, please try again")
			parser.print_help()
			continue

	disconnect_from_peripheral(HoCoSys_peripheral)


if __name__ == "__main__":
	if not os.path.exists("dh_keys") or not os.path.exists("dh_keys/dh_private_key.pem"):
		print("Generating new DH parameters...")
		DH_Param = GenDHParams()
		if not DH_Param:
			print("Error generating DH parameters")
			sys.exit(1)
		save_dh_keys(DH_Param['parameters'], DH_Param['private_key'], DH_Param['public_key_bytes'])
		print("DH parameters generated and saved")
	else:
		print("Loading existing DH parameters...")
		DH_Param = load_dh_keys("dh_keys")
	# Check if DH_Param is valid
	if not isinstance(DH_Param, dict) or 'private_key' not in DH_Param or 'public_key_bytes' not in DH_Param:
		print("Invalid DH parameters loaded")
		sys.exit(1)
	if DH_Param['private_key'] is None or DH_Param['public_key_bytes'] is None:
		print("DH parameters are incomplete")
		sys.exit(1)	
	
	if DH_Param['parameters'] is None:
		print("DH parameters are missing")
		sys.exit(1)
	
	PubKey = DH_Param['public_key_bytes']
	print("Public Key (DER):", binascii.hexlify(DH_Param['public_key_bytes']).decode())
	private_numbers = DH_Param['private_key'].private_numbers()
	print("Private key value (x):", private_numbers.x)
	print("DH Parameters loaded successfully")

	#delegate = MyDelegate()

	ack_tracker = AckTracker()
	sent_frames = {}  #TODO:Populate this after each send
	Global_Seq_Num = Counter()
	asyncio.run(main())
