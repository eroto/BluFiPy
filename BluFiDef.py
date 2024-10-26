#!/user/bin/env python3
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
