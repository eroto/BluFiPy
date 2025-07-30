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

import time

##############
# TYPE Field #
##############
#C O N T R O L   F R A M E S
ACKNOLEDGE	        = 0x00	#Acknowledge
SET_NO_SEC_MODE 	= 0x04	#Set the ESP device security mode, Checksum:NO  Encryption:NO
SET_CHKSUM_ONLY 	= 0x14	#Set the ESP device security mode, Checksum:YES Encryption:NO
SET_ENC_ONLY		= 0x24	#Set the ESP device security mode, Checksum:NO  Encryption:YES
SET_CHKSYM_ENC		= 0x34	#Set the ESP device security mode, Checksum:YES Encryption:YES

SET_WIFI_MODE	= 0x08	#Set the op mode of WIFI
CONN_TO_AP	    = 0x0C	#Connect ESP to AP
DISC_FROM_AP	= 0x10	#Disconnect ESP from AP
GET_WIFI_INFO	= 0x14	#Get information of the ESP WIFI Mode and status
DISC_SOFTAP	    = 0x18	#Disconnect ESP from the SoftAP (in SoftAp Mode)
GET_VERSION	    = 0x1C	#Get version information
DISC_BLE_DEV 	= 0x20	#Disconnect the BLE GATT link
GET_WIFI_LIST	= 0x24	#Get the WIFI slist

#D A T A   F R A M E S
SND_NEG_DATA        = 0x01	#Send the negotiation Data
SND_BSSID_STA       = 0x05	#Send the BSSID for STA mode
SND_SSID_STA        = 0x09	#Send the SSID for STA mode
SND_PWD_STA         = 0x0D	#Send the password for STA mode
SND_SSID_SOFTAP     = 0x11	#Send the SSID for SoftAP mode.
SND_PWD_SOFTAP      = 0x15	#Send the password for SoftAPmode.
SET_MAX_CONN_SOFTAP = 0x19	#Set the maximum connection number for SoftAP mode.
SET_AUTH_SOFTAP     = 0x1D	#Set the authentication mode for SoftAP mode.
SET_NUM_CHN_SOFTAP  = 0x21	#Set the number of channels for SoftAP mode.
SND_USERNAME        = 0x25	#Username
CA_CERT             = 0x29	#CA Certification
CLIENT_CERT         = 0x2D	#Client Certification
SERVER_CERT         = 0x31	#Server Certification
CLIENT_PRIV_KEY     = 0x35	#Client Private Key
SERVER_PRIV_KEY     = 0x39	#Server Private Key
WI_CONN_REPORT      = 0x3D	#Wi-Fi Connection State Report
SND_VERSION         = 0x41	#Version
WIFI_LIST           = 0x45	#Wi-Fi List
REPORT_ERRO         = 0x49	#Report Error
CUSTOM_DATA         = 0x4D	#Custom Data
SET_MAX_RECON_TIME  = 0x51	#Set the maximum Wi-Fi reconnecting time.
SET_WIFI_END_RSN    = 0x55	#Set the Wi-Fi connection end reason.
SET_RSSI_WIFI_CON   = 0x59	#Set the RSSI at Wi-Fi connection end.

#######################
# Frame Control Field #
#######################
#F R A M E   C O N T R O L
#COMMAND                BIT
NOT_ENCRYPTED =	    0x00 # 00000000 : Not encrypted, no checksum
ENCRYPTED = 		0x01 # 00000001 : Encreypted, no checksum
CHKSUM =		    0x02 # 00000010 : Checksum, not encryted
ENC_CHKSUM =		0x03 # 00000011 : encryted and checksum
ESP_T0_MOB =	 	0x04 # 000001xx : from ESP --> MOBILE. / 000000xx Means from ESP <-- MOBILE
ACK_REQ =           0x08 # 00000xxx : not required to reply to an ACK. / 00001xxx: ACK is required
FRAGMENTS =         0x10 # 0001xxxx: there is subsequent data fragment for this frame. /0000xxxx: no subsequent data fragment
# 0x10~0x80 		Reserved


CRC_LENGTH = 2
NOTIFICATION_TIMEOUT = 3.5
MAX_TIMEOUTS = 10
MAX_CHUNK_SIZE = 14


# BlueFiDef class
# This class is used to define the control and data frames for the BluFi protocol.
class BluFiDef():   
    Ctrl_Data = SET_NO_SEC_MODE
    FrmCtrl = NOT_ENCRYPTED

    def __init__(self):
        self.Ctrl_Data = SET_NO_SEC_MODE
        self.FrmCtrl = NOT_ENCRYPTED

    def display_def(self):
        return f"Control/Data: {self.Ctrl_Data}, Frame Control: {self.FrmCtrl}"

    def SetMsgValues(self, val1, val2):
        self.Ctrl_Data = val1
        self.FrmCtrl = val2

#Counter class
#The class is used to counte the messages sequence number
class Counter:
    count = 0
    def __init__(self):
        self.count = 0

    def get_count(self):
        return self.count

    def inc_count(self):
        self.count += 1
        print(f"Counter incremented to->{self.count}")
        return self.count


class AckTracker:
    def __init__(self):
        self.pending_acks = {}  # seq_num: timestamp
        self.received_acks = set()  # confirmed seq_nums

    def mark_sent(self, seq_num: int):
        """Register a frame that expects an ACK."""
        self.pending_acks[seq_num] = time.time()

    def confirm_ack(self, acked_seq: int):
        """Mark a frame as acknowledged."""
        if acked_seq in self.pending_acks:
            del self.pending_acks[acked_seq]
            self.received_acks.add(acked_seq)
            print(f"✅ ACK confirmed for frame #{acked_seq}")
        else:
            print(f"⚠️ Received unexpected ACK for #{acked_seq}")

    def get_missing_acks(self, timeout: float = 2.0):
        """Return list of seq numbers not yet acknowledged within timeout (seconds)."""
        now = time.time()
        return [seq for seq, ts in self.pending_acks.items() if (now - ts) > timeout]

    def reset(self):
        """Clear tracker state (start of new session)."""
        self.pending_acks.clear()
        self.received_acks.clear()