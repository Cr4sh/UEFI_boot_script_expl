
CHIPSEC module that exploits UEFI boot script table vulnerability.

This vulnerability was discovered by Rafal Wojtczuk and Corey Kallenberg, check 
original white paper:

https://frab.cccv.de/system/attachments/2566/original/venamis_whitepaper.pdf


USAGE:

1) Download and install CHIPSEC (https://github.com/chipsec/chipsec).

2) Download and install Capstone engine incl. Python bindings (http://www.capstone-engine.org).

2) Copy boot_script_table.py into the chipsec/source/tool/chipsec/modules.

3) Run module:
   # cd chipsec/source/tool/chipsec
   # python chipsec_main.py --module boot_script_table 


WARNING:

Exploit was designed for Intel DQ77KB motherboard, running this code on any 
other hardware  may lead to unexpected problems due to the different
boot script table format and location.


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh
