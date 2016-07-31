SIG_DOS = 0x5a4d
SIG_OS2 = 0x454e
SIG_OS2LE = 0x454c
SIG_VXD = 0x454c
SIG_NT = 0x4550
MACHINE_INTEL_I386 = 0x14c
MACHINE_INTEL_I486 = 0x14d
MACHINE_INTEL_PENTIUM = 0x14e
MACHINE_MIPS_R3000_BIGENDIAN = 0x160
MACHINE_MIPS_R3000 = 0x162
MACHINE_MIPS_R4000 = 0x166
MACHINE_MIPS_R10000 = 0x168
MACHINE_ALPHA = 0x184
MACHINE_POWERPC = 0x1f0
SIZEOF_IMGDATADIR = 8
DATADIR_EXPORTSYMBOLS = 0
DATADIR_IMPORTSYMBOLS = 1
DATADIR_RESOURCES = 2 
DATADIR_EXCEPTION = 3 
DATADIR_SECURITY = 4 
DATADIR_BASERELOC = 5 
DATADIR_DEBUG = 6 
DATADIR_COPYRIGHTSTRING = 7 
DATADIR_GLOBALPTR = 8 
DATADIR_THREADLOCALSTORAGE = 9 
DATADIR_LOADCONFIG = 10 
DATADIR_BOUNDIMPORT = 11 
DATADIR_IMPORTADDRESSTABLE = 12 
DATADIR_DELAYIMPORT = 13 
DATADIR_COMDESCRIPTOR = 14 
DATADIR_MEMBER16 = 15 
IMG_ORDINAL_FLAG32 = 0x80000000
IMG_CHAR_RELOCS_STRIPPED = 0
IMG_CHAR_EXECUTABLE = 1
IMG_CHAR_LINENUMBERS_STRIPPED = 1 << 1
IMG_CHAR_LOCAL_SYMBOLS_STRIPPED = 1 << 2
IMG_CHAR_AGGRESSIVE_WS_TRIM = 1 << 3
IMG_CHAR_BYTES_REVERSED_LO = 1 << 6
IMG_CHAR_BYTES_REVERSED_HI = 1 << 14
IMG_CHAR_32BIT_MACHINE = 1 << 7
IMG_CHAR_DEBUG_STRIPPED = 1 << 8
IMG_CHAR_REMOVABLE_RUN_FROM_SWAP = 1 << 9
IMG_CHAR_NET_RUN_FROM_SWAP = 1 << 10
IMG_CHAR_SYSTEM_FILE = 1 << 11
IMG_CHAR_DLL = 1 << 12
IMG_CHAR_SINGLE_PROCESSOR_ONLY = 1 << 13
IMG_MAGIC_OPTIONAL_HEADER = 0x10b
SUBSYSTEM_NATIVE = 1
SUBSYSTEM_WINDOWS_GUI = 2
SUBSYSTEM_WINDOWS_CUI = 3
SUBSYSTEM_OS2_CUI = 5
SUBSYSTEM_POSIX_CUI = 7
DLL_CHAR_NOTIF_PROCESS_ATTACH = 1
DLL_CHAR_NOTIF_THREAD_DETACH = 1 << 1
DLL_CHAR_NOTIF_THREAD_ATTACH = 1 << 2
DLL_CHAR_NOTIF_PROCESS_DETACH = 1 << 3
SECTION_ATTR_CODE = 1 << 4
SECTION_ATTR_INITIALIZED_DATA = 1 << 5
SECTION_ATTR_UNINITIALIZED_DATA = 1 << 6
SECTION_ATTR_LINK_INFO = 1 << 8
SECTION_ATTR_LINK_REMOVE = 1 << 10
SECTION_ATTR_LINK_COMMONBLOCKDATA = 1 << 11
SECTION_ATTR_MEMORY_FARDATA = 1 << 14
SECTION_ATTR_MEMORY_PURGEABLE = 1 << 16
SECTION_ATTR_MEMORY_LOCKED = 1 << 17
SECTION_ATTR_MEMORY_PRELOAD = 1 << 18
SECTION_ATTR_BIT20 = 1 << 19
SECTION_ATTR_BIT21 = 1 << 20
SECTION_ATTR_BIT22 = 1 << 21
SECTION_ATTR_BIT23 = 1 << 22
SECTION_ATTR_LINK_NRELOC_OVFL = 1 << 23
SECTION_ATTR_MEMORY_DISCARDABLE = 1 << 24
SECTION_ATTR_MEMORY_NOT_CACHED = 1 << 25
SECTION_ATTR_MEMORY_NOT_PAGED = 1 << 26
SECTION_ATTR_MEMORY_SHARED = 1 << 27
SECTION_ATTR_MEMORY_EXECUTE = 1 << 28
SECTION_ATTR_MEMORY_READ = 1 << 29
SECTION_ATTR_MEMORY_WRITE = 1 << 30

class ImageDataDirectory:
    def __init__(self):
        self.VirtualAddress = 0
        self.isize = 0
    def ReadFromFile(self, fd):
        self.VirtualAddress = fd.read(2) # DWord
        self.isize = fd.read(2)

class ImageDosHeader:
    def __init__(self):
        self.e_magic = 0
        self.e_cblp = 0
        self.e_cp = 0
        self.e_crlc = 0
        self.e_cparhdr = 0
        self.e_minalloc = 0
        self.e_maxalloc = 0
        self.e_ss = 0
        self.e_sp = 0
        self.e_csum = 0
        self.e_ip = 0
        self.e_cs = 0
        self.e_lfarlc = 0
        self.e_ovno = 0
        self.e_res = [0] * 4
        self.e_oemid = 0
        self.e_oeminfo = 0
        self.e_res2 = [0] * 10
        self.e_lfanew = 0
    def ReadFromFile(self, fd):
        self.e_magic = fd.read(2) # Word
        self.e_cblp = fd.read(2) # Word
        self.e_cp = fd.read(2) # Word
        self.e_crlc = fd.read(2) # Word
        self.e_cparhdr = fd.read(2) # Word
        self.e_minalloc = fd.read(2) # Word
        self.e_maxalloc = fd.read(2) # Word
        self.e_ss = fd.read(2) # Word
        self.e_sp = fd.read(2) # Word
        self.e_csum = fd.read(2) # Word
        self.e_ip = fd.read(2) # Word
        self.e_cs = fd.read(2) # Word
        self.e_lfarlc = fd.read(2) # Word
        self.e_ovno = fd.read(2) # Word
        self.e_res = fd.read(8) # Word * 4
        self.e_oemid = fd.read(2) # Word
        self.e_oeminfo = fd.read(2) # Word
        self.e_res2 = fd.read(20) # Word * 10
        self.e_lfanew = fd.read(4) # Dword

class ImageFileHeader:
    def __init__(self):
        self.Machine = 0
        self.NumberOfSections = 0
        self.TimeDateStamp = 0
        self.PointerToSymbolTable = 0
        self.NumberOfSymbols = 0
        self.SizeOfOptionalHeader = 0
        self.Characteristics = 0
    def ReadFromFile(self, fd):
        self.Machine = fd.read(2) # Word
        self.NumberOfSections = fd.read(2) # Word
        self.TimeDateStamp = fd.read(4) # DWord
        self.PointerToSymbolTable = fd.read(4) # DWord
        self.NumberOfSymbols = fd.read(4) # Dword
        self.SizeOfOptionalHeader = fd.read(2) # Word
        self.Characteristics = fd.read(2) # Word

class ImageOptionalHeader32:
    def __init__(self):
        self.Magic = 0
        self.MajorLinkerVersion = 0
        self.MinorLinkerVersion = 0
        self.SizeOfCode = 0
        self.SizeOfInitializedData = 0
        self.SizeOfUninitializedDtat = 0
        self.AddressOfEntryPoint = 0
        self.BaseOfCode = 0
        self.BaseOfData = 0
        self.ImageBase = 0
        self.SectionAlignment = 0
        self.FileAlignment = 0
        self.MajorOperatingSystemVersion = 0
        self.MinorOperatingSystemVersion = 0
        self.MajorImageVersion = 0
        self.MinorImageVersion = 0
        self.MajorSubsystemVersion = 0
        self.MinorSubsystemVersion = 0
        self.Win32VersionValue = 0
        self.SizeOfImage = 0
        self.SizeOfHeaders = 0
        self.CheckSum = 0
        self.Subsystem = 0
        self.DllCharacteristics = 0
        self.SizeOfStackReserve = 0
        self.SizeOfStackCommit = 0
        self.SizeOfHeapReserve = 0
        self.SizeOfHeapCommit = 0
        self.LoaderFlags = 0
        self.NumberOfRvaAndSizes = 0
        self.DataDirectory = None
    def ReadFromFile(self, fd):
        self.Magic = fd.read(2) # Word
        self.MajorLinkerVersion = fd.read(1) # Byte
        self.MinorLinkerVersion = fd.read(1) # Byte
        self.SizeOfCode = fd.read(4) # DWord
        self.SizeOfInitializedData = fd.read(4) # DWord
        self.SizeOfUninitializedDtat = fd.read(4) # DWord
        self.AddressOfEntryPoint = fd.read(4) # DWord
        self.BaseOfCode = fd.read(4) # DWord
        self.BaseOfData = fd.read(4) # DWord
        self.ImageBase = fd.read(4) # DWord
        self.SectionAlignment = fd.read(4) # DWord
        self.FileAlignment = fd.read(4) # DWord
        self.MajorOperatingSystemVersion = fd.read(2)
        self.MinorOperatingSystemVersion = fd.read(2)
        self.MajorImageVersion = fd.read(2)
        self.MinorImageVersion = fd.read(2)
        self.MajorSubsystemVersion = fd.read(2)
        self.MinorSubsystemVersion = fd.read(2)
        self.Win32VersionValue = fd.read(4) # DWord
        self.SizeOfImage = fd.read(4) # DWord
        self.SizeOfHeaders = fd.read(4) # DWord
        self.CheckSum = fd.read(4) # DWord
        self.Subsystem = fd.read(2)
        self.DllCharacteristics = fd.read(2)
        self.SizeOfStackReserve = fd.read(4) # DWord
        self.SizeOfStackCommit = fd.read(4) # DWord
        self.SizeOfHeapReserve = fd.read(4) # DWord
        self.SizeOfHeapCommit = fd.read(4) # DWord
        self.LoaderFlags = fd.read(4) # DWord
        self.NumberOfRvaAndSizes = fd.read(4) # DWord
        self.DataDirectory = []
        for i in range(0, 16):
            dd = ImageDataDirectory()
            dd.ReadFromFile(fd)
            self.DataDirectory.append(dd)
        
class ImageSectionHeader:
    def __init__(self):
        self.Name = " "*8
        self.PhysicalAddress = 0
        self.VirtualSize = 0
        self.VirtualAddress = 0
        self.SizeOfRawData = 0
        self.PointerToRawData = 0
        self.PointerToRelocations = 0
        self.PointerToLineNumbers = 0
        self.NumberOfRelocations = 0
        self.NumberOfLineNumbers = 0
        self.Characteristics = 0
    def ReadFromFile(self, fd):
        self.Name = fd.read(8) # char[8]
        self.PhysicalAddress = fd.read(4) # DWord
        self.VirtualSize = fd.read(4) # DWord
        self.VirtualAddress = fd.read(4) # DWord
        self.SizeOfRawData = fd.read(4) # DWord
        self.PointerToRawData = fd.read(4) # DWord
        self.PointerToRelocations = fd.read(4) # DWord
        self.PointerToLineNumbers = fd.read(4) # DWord
        self.NumberOfRelocations = fd.read(2) # Word
        self.NumberOfLineNumbers = fd.read(2) # Word
        self.Characteristics = fd.read(4) # DWord
        
class ImageNtHeaders:
    def __init__(self):
        self.Signature = 0
        self.FileHeader = None
        self.OptionalHeader = None
    def ReadFromFile(self, fd):
        self.Signature = fd.read(4) # Dword
        self.FileHeader = ImageFileHeader()
        self.FileHeader.ReadFromFile(fd)
        self.OptionalHeader = ImageOptionalHeader32()
        self.OptionalHeader.ReadFromFile(fd)

class ImageImportDescriptor:
    def __init__(self):
        self.Characteristics = 0
        self.OriginalFirstThunk = 0
        self.TimeDateStamp = 0
        self.ForwarderChain = 0
        self.Name = 0
        self.FirstThunk = 0
    def ReadFromFile(self, fd):
        self.Characteristics = fd.read(4) # DWord
        self.OriginalFirstThunk = fd.read(4) # DWord
        self.TimeDateStamp = fd.read(4) # DWord
        self.ForwarderChain = fd.read(4) # DWord
        self.Name = fd.read(4) # DWord
        self.FirstThunk = fd.read(4) # DWord

class ImageImportByName:
    def __init__(self):
        self.Hint = 0
        self.Name = "" # ASCIZ
    def ReadFromFile(self, fd):
        self.Hint = fd.read(4) # DWord
        self.Name = utils.ReadAsciz() # ASCIIZ

class ImageExportDirectory:
    def __init__(self):
        self.Characteristics = 0
        self.TimeDateStamp = 0
        self.MajorVersion = 0
        self.MinorVersion = 0
        self.nName = 0
        self.nBase = 0
        self.NumberOfFunctions = 0
        self.NumberOfNames = 0
        self.AddressOfFunctions = 0
        self.AddressOfNames = 0
        self.AddressOfNameOrdinals = 0
    def ReadFromFile(self, fd):
        self.Characteristics = fd.read(4) # DWord
        self.TimeDateStamp = fd.read(4) # DWord
        self.MajorVersion = fd.read(2) # Word
        self.MinorVersion = fd.read(2) # Word
        self.nName = fd.read(4) # DWord
        self.nBase = fd.read(4) # DWord
        self.NumberOfFunctions = fd.read(4) # DWord
        self.NumberOfNames = fd.read(4) # DWord
        self.AddressOfFunctions = fd.read(4) # DWord
        self.AddressOfNames = fd.read(4) # DWord
        self.AddressOfNameOrdinals = fd.read(4) # DWord
