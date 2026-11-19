# probe_tonesignal.gdb - observation script for CFE_TIME_ToneSignalCmd
# Prints one line for every entry into the handler, with a running count.
# The breakpoint only prints; it does not participate in message delivery.
# The counter is a gdb convenience variable; it lives in this gdb session only.
#
# Run (this script starts the instance; run the trigger from another terminal):
#   gdb -nx -batch -x probe_tonesignal.gdb --args ./core-cpu1
#   python3 poc_tone_signal.py            # trigger: ten malformed TONE_CMD frames
#
# Baseline: about one line per second (the internal 1 Hz tone task enters the
# same handler). After the trigger the count jumps accordingly, with no
# rejection event. Contrast: send_hdr_frames.py --mid=0x1805 --fc=4 produces no
# handler line; the console prints "Invalid msg length" instead.
set pagination off
set confirm off
set $th = 0
break CFE_TIME_ToneSignalCmd
commands
silent
set $th = $th + 1
printf "TONE_CMD handler entered (count=%d)\n", $th
continue
end
run
