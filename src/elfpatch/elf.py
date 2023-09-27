from dataclasses import dataclass
from typing import Union
from .ptypes import Structure
from .ptypes import p_int32
from .ptypes import p_int64
from .ptypes import p_uint8
from .ptypes import p_uint16
from .ptypes import p_uint32
from .ptypes import p_uint64
from .ptypes import sizeof

Elf32_Half = p_uint16
Elf32_Word = p_uint32
Elf32_Sword = p_int32
Elf32_Addr = p_uint32
Elf32_Off = p_uint32

Elf64_Half = p_uint16
Elf64_Word = p_uint32
Elf64_Sword = p_int32
Elf64_Xword = p_uint64
Elf64_Sxword = p_int64
Elf64_Addr = p_uint64
Elf64_Off = p_uint64

# The four ELF magic number parts
ELF_MAGIC = (0x7F, ord("E"), ord("L"), ord("F"))

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1  # 2's complement, little endian
ELFDATA2MSB = 2  # 2's complement, big endian

ET_DYN = 3  # Shared object file

PT_NULL = 0  # Program header table entry unused
PT_LOAD = 1  # Loadable program segment
PT_DYNAMIC = 2  # Dynamic linking information
PT_INTERP = 3  # Program interpreter
PT_NOTE = 4  # Auxiliary information
PT_SHLIB = 5  # Reserved
PT_PHDR = 6  # Entry for header table itself
PT_TLS = 7  # Thread-local storage segment
PT_NUM = 8  # Number of defined types
PT_GNU_RELRO = 0x6474E552

PF_R = 0x4
PF_W = 0x2
PF_X = 0x1

SHT_STRTAB = 3
SHT_DYNAMIC = 6

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF


class ElfIdent(Structure):
    _fields_ = [
        ("ei_mag0", p_uint8),
        ("ei_mag1", p_uint8),
        ("ei_mag2", p_uint8),
        ("ei_mag3", p_uint8),
        ("ei_class", p_uint8),
        ("ei_data", p_uint8),
        ("ei_version", p_uint8),
        ("ei_osabi", p_uint8),
        ("ei_abiversion", p_uint8),
        ("ei_pad1", p_uint8),
        ("ei_pad2", p_uint8),
        ("ei_pad3", p_uint8),
        ("ei_pad4", p_uint8),
        ("ei_pad5", p_uint8),
        ("ei_pad6", p_uint8),
        ("ei_pad7", p_uint8),
    ]


_Elf32_Ehdr_fields = [
    *ElfIdent._fields_,
    ("e_type", Elf32_Half),
    ("e_machine", Elf32_Half),
    ("e_version", Elf32_Word),
    ("e_entry", Elf32_Addr),
    ("e_phoff", Elf32_Off),
    ("e_shoff", Elf32_Off),
    ("e_flags", Elf32_Word),
    ("e_ehsize", Elf32_Half),
    ("e_phentsize", Elf32_Half),
    ("e_phnum", Elf32_Half),
    ("e_shentsize", Elf32_Half),
    ("e_shnum", Elf32_Half),
    ("e_shstrndx", Elf32_Half),
]


class Elf32_Ehdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Ehdr_fields


class Elf32_Ehdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Ehdr_fields


_Elf64_Ehdr_fields = [
    *ElfIdent._fields_,
    ("e_type", Elf64_Half),
    ("e_machine", Elf64_Half),
    ("e_version", Elf64_Word),
    ("e_entry", Elf64_Addr),
    ("e_phoff", Elf64_Off),
    ("e_shoff", Elf64_Off),
    ("e_flags", Elf64_Word),
    ("e_ehsize", Elf64_Half),
    ("e_phentsize", Elf64_Half),
    ("e_phnum", Elf64_Half),
    ("e_shentsize", Elf64_Half),
    ("e_shnum", Elf64_Half),
    ("e_shstrndx", Elf64_Half),
]


class Elf64_Ehdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Ehdr_fields


class Elf64_Ehdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Ehdr_fields


_Elf32_Phdr_fields = [
    ("p_type", Elf32_Word),
    ("p_offset", Elf32_Off),
    ("p_vaddr", Elf32_Addr),
    ("p_paddr", Elf32_Addr),
    ("p_filesz", Elf32_Word),
    ("p_memsz", Elf32_Word),
    ("p_flags", Elf32_Word),
    ("p_align", Elf32_Word),
]


class Elf32_Phdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Phdr_fields


class Elf32_Phdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Phdr_fields


_Elf64_Phdr_fields = [
    ("p_type", Elf64_Word),
    ("p_flags", Elf64_Word),
    ("p_offset", Elf64_Off),
    ("p_vaddr", Elf64_Addr),
    ("p_paddr", Elf64_Addr),
    ("p_filesz", Elf64_Xword),
    ("p_memsz", Elf64_Xword),
    ("p_align", Elf64_Xword),
]


class Elf64_Phdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Phdr_fields


class Elf64_Phdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Phdr_fields


_Elf32_Shdr_fields = [
    ("sh_name", Elf32_Word),
    ("sh_type", Elf32_Word),
    ("sh_flags", Elf32_Word),
    ("sh_addr", Elf32_Addr),
    ("sh_offset", Elf32_Off),
    ("sh_size", Elf32_Word),
    ("sh_link", Elf32_Word),
    ("sh_info", Elf32_Word),
    ("sh_addralign", Elf32_Word),
    ("sh_entsize", Elf32_Word),
]


class Elf32_Shdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Shdr_fields


class Elf32_Shdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Shdr_fields


_Elf64_Shdr_fields = [
    ("sh_name", Elf64_Word),
    ("sh_type", Elf64_Word),
    ("sh_flags", Elf64_Xword),
    ("sh_addr", Elf64_Addr),
    ("sh_offset", Elf64_Off),
    ("sh_size", Elf64_Xword),
    ("sh_link", Elf64_Word),
    ("sh_info", Elf64_Word),
    ("sh_addralign", Elf64_Xword),
    ("sh_entsize", Elf64_Xword),
]


class Elf64_Shdr_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Shdr_fields


class Elf64_Shdr_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Shdr_fields


_Elf32_Dyn_fields = [
    ("d_tag", Elf32_Sword),
    ("d_ptr_or_val", Elf32_Addr),  # union of d_ptr and d_val
]


class Elf32_Dyn_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Dyn_fields


class Elf32_Dyn_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Dyn_fields


_Elf64_Dyn_fields = [
    ("d_tag", Elf64_Sxword),
    ("d_ptr_or_val", Elf64_Addr),  # union of d_ptr and d_val
]


class Elf64_Dyn_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Dyn_fields


class Elf64_Dyn_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Dyn_fields


_Elf32_Sym_fields = [
    ("st_name", Elf32_Word),
    ("st_value", Elf32_Addr),
    ("st_size", Elf32_Word),
    ("st_info", p_uint8),
    ("st_other", p_uint8),
    ("st_shndx", Elf32_Half),
]


class Elf32_Sym_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Sym_fields


class Elf32_Sym_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Sym_fields


_Elf64_Sym_fields = [
    ("st_name", Elf64_Word),
    ("st_info", p_uint8),
    ("st_other", p_uint8),
    ("st_shndx", Elf64_Half),
    ("st_value", Elf64_Addr),
    ("st_size", Elf64_Xword),
]


class Elf64_Sym_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Sym_fields


class Elf64_Sym_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Sym_fields


_Elf32_Verneed_fields = [
    ("vn_version", Elf32_Half),
    ("vn_cnt", Elf32_Half),
    ("vn_file", Elf32_Word),
    ("vn_aux", Elf32_Word),
    ("vn_next", Elf32_Word),
]


class Elf32_Verneed_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Verneed_fields


class Elf32_Verneed_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Verneed_fields


_Elf64_Verneed_fields = [
    ("vn_version", Elf64_Half),
    ("vn_cnt", Elf64_Half),
    ("vn_file", Elf64_Word),
    ("vn_aux", Elf64_Word),
    ("vn_next", Elf64_Word),
]


class Elf64_Verneed_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Verneed_fields


class Elf64_Verneed_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Verneed_fields


_Elf32_Vernaux_fields = [
    ("vna_hash", Elf32_Word),
    ("vna_flags", Elf32_Half),
    ("vna_other", Elf32_Half),
    ("vna_name", Elf32_Word),
    ("vna_next", Elf32_Word),
]


class Elf32_Vernaux_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf32_Vernaux_fields


class Elf32_Vernaux_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf32_Vernaux_fields


_Elf64_Vernaux_fields = [
    ("vna_hash", Elf64_Word),
    ("vna_flags", Elf64_Half),
    ("vna_other", Elf64_Half),
    ("vna_name", Elf64_Word),
    ("vna_next", Elf64_Word),
]


class Elf64_Vernaux_BE(Structure):
    _endian_ = ">"
    _fields_ = _Elf64_Vernaux_fields


class Elf64_Vernaux_LE(Structure):
    _endian_ = "<"
    _fields_ = _Elf64_Vernaux_fields


Elf_Ehdr = Union[Elf32_Ehdr_BE, Elf32_Ehdr_LE, Elf64_Ehdr_BE, Elf64_Ehdr_LE]
Elf_Phdr = Union[Elf32_Phdr_BE, Elf32_Phdr_LE, Elf64_Phdr_BE, Elf64_Phdr_LE]
Elf_Shdr = Union[Elf32_Shdr_BE, Elf32_Shdr_LE, Elf64_Shdr_BE, Elf64_Shdr_LE]
Elf_Dyn = Union[Elf32_Dyn_BE, Elf32_Dyn_LE, Elf64_Dyn_BE, Elf64_Dyn_LE]
Elf_Sym = Union[Elf32_Sym_BE, Elf32_Sym_LE, Elf64_Sym_BE, Elf64_Sym_LE]
Elf_Verneed = Union[Elf32_Verneed_BE, Elf32_Verneed_LE, Elf64_Verneed_BE, Elf64_Verneed_LE]
Elf_Vernaux = Union[Elf32_Vernaux_BE, Elf32_Vernaux_LE, Elf64_Vernaux_BE, Elf64_Vernaux_LE]


@dataclass
class ElfClass:
    alignment: int
    Ehdr: Elf_Ehdr
    Phdr: Elf_Phdr
    Shdr: Elf_Shdr
    Dyn: Elf_Dyn
    Sym: Elf_Sym
    Verneed: Elf_Verneed
    Vernaux: Elf_Vernaux


ELF32_CLASS_BE = ElfClass(
    alignment=sizeof(Elf32_Off),
    Ehdr=Elf32_Ehdr_BE,
    Phdr=Elf32_Phdr_BE,
    Shdr=Elf32_Shdr_BE,
    Dyn=Elf32_Dyn_BE,
    Sym=Elf32_Sym_BE,
    Verneed=Elf32_Verneed_BE,
    Vernaux=Elf32_Vernaux_BE,
)

ELF32_CLASS_LE = ElfClass(
    alignment=sizeof(Elf32_Off),
    Ehdr=Elf32_Ehdr_LE,
    Phdr=Elf32_Phdr_LE,
    Shdr=Elf32_Shdr_LE,
    Dyn=Elf32_Dyn_LE,
    Sym=Elf32_Sym_LE,
    Verneed=Elf32_Verneed_LE,
    Vernaux=Elf32_Vernaux_LE,
)

ELF64_CLASS_BE = ElfClass(
    alignment=sizeof(Elf64_Off),
    Ehdr=Elf64_Ehdr_BE,
    Phdr=Elf64_Phdr_BE,
    Shdr=Elf64_Shdr_BE,
    Dyn=Elf64_Dyn_BE,
    Sym=Elf64_Sym_BE,
    Verneed=Elf64_Verneed_BE,
    Vernaux=Elf64_Vernaux_BE,
)

ELF64_CLASS_LE = ElfClass(
    alignment=sizeof(Elf64_Off),
    Ehdr=Elf64_Ehdr_LE,
    Phdr=Elf64_Phdr_LE,
    Shdr=Elf64_Shdr_LE,
    Dyn=Elf64_Dyn_LE,
    Sym=Elf64_Sym_LE,
    Verneed=Elf64_Verneed_LE,
    Vernaux=Elf64_Vernaux_LE,
)
