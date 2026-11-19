#!/usr/bin/env python3
# send_hdr_frames.py - header-only frame sender (contrast / observation aid)
# Sends frames declaring a payload length of 1 - a bare 8-byte CCSDS header -
# followed by 8 trailing 0xAB marker bytes, to the given message ID.
# Pure trigger: no observation output; read the target console.
#
# Usage:
#   python3 send_hdr_frames.py [--mid=0x1805] [--fc=4] [--ip=127.0.0.1]
#                              [--port=1334] [--count=1]
#   Contrast for CFE_TIME_ToneSignalCmd: --mid=0x1805 --fc=4 (validated
#   ground-command MID; the console prints "Invalid msg length")
import socket
import struct
import sys
import time


def build_cmd(mid, fc, payload=b""):
    """cFE command: 6B primary header + 2B secondary (fc, checksum) + payload;
    length field = total - 7"""
    apid = mid & 0x7FF
    byte0 = (0 << 5) | (1 << 4) | (1 << 3) | ((apid >> 8) & 0x7)
    total = 8 + len(payload)
    pkt = bytearray(struct.pack(">BBHH", byte0, apid & 0xFF, 0xC000, total - 7))
    pkt.append(fc)
    pkt.append(0x00)
    pkt += payload
    chk = 0xFF
    for b in pkt:
        chk ^= b
    pkt[7] = chk  # CFE_MSG_ComputeCheckSum: 0xFF-seeded XOR; whole-packet XOR must be 0
    return bytes(pkt)


def main():
    a = {"mid": "0x1805", "fc": 0, "ip": "127.0.0.1", "port": 1334, "count": 1}
    for x in sys.argv[1:]:
        k, _, v = x.lstrip("-").partition("=")
        k = k.replace("-", "_")
        if k in a:
            a[k] = int(v, 16) if k == "mid" else int(v)
    frame = build_cmd(a["mid"], a["fc"], b"") + b"\xAB" * 8
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(a["count"]):
        s.sendto(frame, (a["ip"], a["port"]))
        time.sleep(0.1)
    print("[*] sent %d header-only frames to MID=0x%04X (%s:%d)"
          % (a["count"], a["mid"], a["ip"], a["port"]))


if __name__ == "__main__":
    main()
