#!/bin/zsh

cfg="openocd.cfg"
gdb="openocd.gdb"

cat << EOF > "$cfg"
source [ find /home/ectf2025/MaximSDK/Tools/OpenOCD/scripts/interface/cmsis-dap.cfg ]
source [find target/max78000.cfg]
adapter serial 0423170217becac900000000000000000000000097969906
gdb_port 50007
tcl_port 50008
telnet_port 50009
EOF

cat << EOF > "$gdb"
target extended-remote :50007

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
