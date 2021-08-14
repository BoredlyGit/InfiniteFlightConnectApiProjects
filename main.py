# Code borrowed from https://github.com/flyme2bluemoon/InfiniteFlightConnect-Python
# Reference: https://infiniteflight.com/guide/developer-reference/connect-api/version-2

import socket
import json
from binascii import unhexlify
import time

# UDP is connectionless, so packets do not have a designated destination, allowing anyone to pick them up. This also
# means no connect() or accept(). IF sends packets containing the app and device info to port 15000
# https://stackoverflow.com/questions/6189831/whats-the-purpose-of-using-sendto-recvfrom-instead-of-connect-send-recv





"""
Data Types (Read and Write):
- Int: 32-bit (4 bytes) signed int in little endian
- String: utf-8 strings, can be decoded simply via bytes.decode()

"""


class IFConnect:
    def __init__(self):
        self.device_info = None
        self.device_ip = None
        self.device_port = 10112  # IF Connect v2 receives on this port
        self.tcp = None

    def receive_int(self):
        """
        Receives bytes from the tcp socket and converts them int an int. The bytes are interpreted as 32-bit (4 byte),
        big endian, signed integers.

        :return: (4) Bytes in the TCP socket buffer, converted into an int.
        :rtype: int
        """
        return int.from_bytes(self.tcp.recv(4), "little", signed=True)

    def receive_string(self):
        return self.tcp.recv(self.receive_int()).decode()

    def connect_tcp(self, device_ip=None):
        if not device_ip:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # SOCK_DGRAM (datagram) = UDP
            udp.bind(("", 15000))
            while True:
                self.device_info, addr = (udp.recvfrom(4096))
                if self.device_info:
                    self.device_info = json.loads(self.device_info.decode())
                    udp.close()
                    break

            self.device_ip = addr[0]
        else:
            self.device_ip = device_ip

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # SOCK_STREAM = TCP
        # In this case, we are the client, so no need to call bind() and accept()
        self.tcp.connect((self.device_ip, self.device_port))
        print(f"Connected to Infinite Flight Connect: {self.device_info['DeviceName']}, ip: {self.device_ip}")

    def get_manifest(self):
        # Suggestion: 32-bit python cannot support this yet, the manifest length int is too large. Find a bypass.
        # NOTE: Different aircraft have different manifests
        a = -1
        self.tcp.sendall(a.to_bytes(4, "little", signed=True))
        self.tcp.sendall(False.to_bytes(5, "big"))

        time.sleep(1)  # Manifest is very large, so it is sent in chunks, have to account for the delay.
        assert int.from_bytes(self.tcp.recv(4), "little", signed=True) == -1  # api returns -1 as acknowledgement

        manifest = self.receive_string()
        # this may cause issues, as the [4:] cuts out the string "172 ", which I do not know the purpose of.
        return [item.split(",") for item in manifest[4:].split("\n")]


class Manifest:
    # TODO
    pass


z = IFConnect()
z.connect_tcp()
print(z.get_manifest())
