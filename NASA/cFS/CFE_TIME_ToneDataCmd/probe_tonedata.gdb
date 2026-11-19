# probe_tonedata.gdb - observation script for CFE_TIME_ToneDataCmd
# Prints one line for every step of the tone chain: TONEDATA for each DATA_CMD
# entering CFE_TIME_ToneData (with the payload fields it read), ERR1/ERR2/ERR3
# for the three rejection conditions of CFE_TIME_ToneVerify, MATCH for a pass,
# and TONEUPDATE for every entry into CFE_TIME_ToneUpdate with the pending
# values about to be loaded. The breakpoints only print; they do not
# participate in message delivery.
#
# Run (this script starts the instance; run the trigger from another terminal):
#   gdb -nx -batch -x probe_tonedata.gdb --args ./core-cpu1
#   python3 poc_tone_data.py            # trigger: header-only frames + three ONEHZ/DATA pairs
#
# Header-only frames show TONEDATA lines whose MET/STCF fields are adjacent
# memory the frames never carried (the out-of-bounds read). A paired round
# ends in MATCH followed by TONEUPDATE: Loading pending MET=<injected value>.
# Baseline: the internal tone task of a server build produces occasional
# TONEDATA/MATCH lines of its own, interleaved with the periodic Start/Stop
# FLYWHEEL events of the time state machine.
set pagination off
set confirm off
break cfe_time_tone.c:695
commands
silent
printf "ERR1-replayPrev1: T1=%u.%u Prev1=%u.%u\n", Time1.Seconds, Time1.Subseconds, PrevTime1.Seconds, PrevTime1.Subseconds
continue
end
break cfe_time_tone.c:702
commands
silent
printf "ERR2-replayPrev2: T2=%u.%u Prev2=%u.%u\n", Time2.Seconds, Time2.Subseconds, PrevTime2.Seconds, PrevTime2.Subseconds
continue
end
break cfe_time_tone.c:735
commands
silent
printf "ERR3-window: T1=%u.%u T2=%u.%u elapsedS=%u elapsedSS=%u min=%u max=%u\n", Time1.Seconds, Time1.Subseconds, Time2.Seconds, Time2.Subseconds, elapsed.Seconds, elapsed.Subseconds, CFE_TIME_Global.MinElapsed, CFE_TIME_Global.MaxElapsed
continue
end
break cfe_time_tone.c:739
commands
silent
printf "MATCH: T1=%u.%u T2=%u.%u\n", Time1.Seconds, Time1.Subseconds, Time2.Seconds, Time2.Subseconds
continue
end
break CFE_TIME_ToneUpdate
commands
silent
printf "TONEUPDATE: Loading pending MET=%u STCF=%u leaps=%d\n", CFE_TIME_Global.PendingMET.Seconds, CFE_TIME_Global.PendingSTCF.Seconds, CFE_TIME_Global.PendingLeaps
continue
end
break CFE_TIME_ToneData
commands
silent
printf "TONEDATA: MET=%u STCF=%u leaps=%d state=%d\n", ToneDataCmd->AtToneMET.Seconds, ToneDataCmd->AtToneSTCF.Seconds, ToneDataCmd->AtToneLeapSeconds, ToneDataCmd->AtToneState
continue
end
run
