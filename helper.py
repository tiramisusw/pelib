import util
import internals

class PeFileReader:
    def ReadDosHeader(self):
        """Reads DOS header from file into object."""
        doshd = internals.ImageDosHeader()
        doshd.ReadFromFile(self.FileDescriptor)
        self.DosHeader = doshd
    def GetPeHeaderOffset(self):
        """Returns PE header offset relative to file beginning."""
        if self.DosHeader is None: self.ReadDosHeader()
        return util.Dword(self.DosHeader.e_lfanew)
    def ReadPeHeader(self):
        """Reads PE header from file into object."""
        self.FileDescriptor.seek(self.GetPeHeaderOffset())
        pehd = internals.ImageNtHeaders()
        pehd.ReadFromFile(self.FileDescriptor)
        self.PeHeader = pehd
    def ReadHeaders(self):
        """Reads both DOS and PE headers."""
        if self.DosHeader is None: self.ReadDosHeader()
        if self.PeHeader is None: self.ReadPeHeader()
    def __init__(self, fd):
        """Provides interface to access PE file information."""
        self.FileDescriptor = fd
        self.DosHeader = None
        self.PeHeader = None
    def LoadFromFile(path):
        """Reads PE file from path."""
        fdesc = open(path, "rb+")
        Me = PeFileReader(fdesc)
        isvalid = Me.ValidateFile()
        if not isvalid:
            raise ValueError("This file is not a PE executable.")
        else:
            return Me
    def ValidateFile(self):
        """Validates executable file using both headers."""
        self.ReadHeaders()
        if util.Dword(self.DosHeader.e_magic) != internals.SIG_DOS:
            # DOS signature invalid.
            return False
        elif util.Dword(self.PeHeader.Signature) != internals.SIG_NT:
            # PE signature invalid.
            return False
        return True
    def ReadCpuArchitectureNumber(self):
        """Reads processor architecture number of the executable."""
        return util.Word(self.PeHeader.FileHeader.Machine)
    def ReadCpuArchitecture(self):
        """Reads processor architecture in human-readable form."""
        proc = self.ReadCpuArchitectureNumber()
        if proc == internals.MACHINE_INTEL_I386:
            return "intel i386"
        elif proc == internals.MACHINE_INTEL_I486:
            return "intel i486+"
        elif proc == internals.MACHINE_INTEL_PENTIUM:
            return "intel pentium"
        elif proc == internals.MACHINE_MIPS_R3000_BIGENDIAN:
            return "mips r3000 big-endian"
        elif proc == internals.MACHINE_MIPS_R3000:
            return "mips r3000 little-endian"
        elif proc == internals.MACHINE_MIPS_R4000:
            return "mips r4000"
        elif proc == internals.MACHINE_MIPS_R10000:
            return "mips r10000"
        elif proc == internals.MACHINE_ALPHA:
            return "alpha"
        elif proc == internals.MACHINE_POWERPC:
            return "powerpc"
        else:
            return "unknown"
    def ReadNumberOfSections(self):
        """Reads number of sections resides in the file."""
        self.ReadHeaders()
        return util.Word(self.PeHeader.FileHeader.NumberOfSections)
    def ReadEntryPointRVA(self):
        """Reads RVA of entry point."""
        self.ReadHeaders()
        return util.Dword(self.PeHeader.OptionalHeader.AddressOfEntryPoint)
    def ReadPreferredImageBase(self):
        """Reads preferred load address of file."""
        self.ReadHeaders()
        return util.Dword(self.PeHeader.OptionalHeader.ImageBase)
    def ReadSectionAlignment(self):
        """Reads memory sections alignment of file."""
        self.ReadHeaders()
        return util.Dword(self.PeHeader.OptionalHeader.SectionAlignment)
    def ReadWin32SubsystemVersion(self):
        """Reads win32 subsystem version used in the file."""
        self.ReadHeaders()
        return (util.Word(self.PeHeader.OptionalHeader.MajorSubsystemVersion),
                util.Word(self.PeHeader.OptionalHeader.MinorSubsystemVersion))
