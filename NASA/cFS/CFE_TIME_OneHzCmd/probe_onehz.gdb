# probe_onehz.gdb - observation script for CFE_TIME_OneHzCmd
# Prints one line for every entry into the handler, with a running count.
# The breakpoint only prints; it does not participate in message delivery.
# The counter is a gdb convenience variable; it lives in this gdb session only.
#
# Run (this script starts the instance; run the trigger from another terminal):
#   gdb -nx -batch -x probe_onehz.gdb --args ./core-cpu1
#   python3 poc_onehz.py            # trigger: ten malformed ONEHZ_CMD frames
#
# Baseline: about one line per second (the internal 1 Hz task of TIME enters
# the same handler). After the trigger the count jumps accordingly, with no
# rejection event. Contrast: send_hdr_frames.py --mid=0x1805 --fc=4 produces no
# handler line; the console prints "Invalid msg length" instead.
set pagination off
set confirm off
set $oh = 0
break CFE_TIME_OneHzCmd
commands
silent
set $oh = $oh + 1
printf "ONEHZ handler entered (count=%d)\n", $oh
continue
end
run
