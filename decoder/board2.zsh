#!/bin/zsh

cfg="openocd.cfg"
gdb="openocd.gdb"

cat << EOF > "$cfg"
source [ find /home/ectf2025/MaximSDK/Tools/OpenOCD/scripts/interface/cmsis-dap.cfg ]
source [find target/max78000.cfg]
adapter serial 04231702e3c6c86a00000000000000000000000097969906
gdb_port 50004
tcl_port 50005
telnet_port 50006
EOF

cat << EOF > "$gdb"
target extended-remote :50004

# print demangled symbols
set print asm-demangle on

# set backtrace limit to not have infinite backtrace loops
set backtrace limit 32

# detect unhandled exceptions, hard faults and panics
break DefaultHandler
break HardFault
break rust_begin_unwind
# # run the next few lines so the panic message is printed immediately
# # the number needs to be adjusted for your panic handler
# commands $bpnum
# next 4
# end

# *try* to stop at the user entry point (it might be gone due to inlining)
break main

# enable semihosting
monitor arm semihosting enable

# load the program
load

# start the process but immediately halt the processor
stepi
EOF
