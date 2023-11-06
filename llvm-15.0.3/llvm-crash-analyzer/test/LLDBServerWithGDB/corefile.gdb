set pagination off

print coremaker_data
print coremaker_bss
print coremaker_ro
print func2::coremaker_local

backtrace
info registers

x/8bd buf1
x/8bd buf2

quit
