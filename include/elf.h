#ifndef ELF_H_
#define ELF_H_

#include <stdint.h>

/*=== ELF identification indexes and values ===*/
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_PAD 7
#define EI_NIDENT 16
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
/* Invalid class */
#define ELFCLASSNONE 0
/* 32-bit objects */
#define ELFCLASS32 1
/* 64-bit objects */
#define ELFCALSS64 2
/* Invalid data encoding */
#define ELFDATANONE 0
/* Little-endian */
#define ELFDATA2LSB 1
/* Big-endian */
#define ELFDATA2MSB 2

/*=== Values for e_type ===*/
/* No file type */
#define ET_NONE 0
/* Relocatable file */
#define ET_REL 1
/* Executable file */
#define ET_EXEC 2
/* Shared object file */
#define ET_DYN 3
/* Core file */
#define ET_CORE 4
/* Processor specific */
#define ET_LOPROC 0xff00
/* Processor specific */
#define ET_HIPROC 0xffff

/*=== Values for e_machine ===*/
/* No machine */
#define EM_NONE 0
/* AT&T WE 32100 */
#define EM_M32 1
/* SPARC */
#define EM_SPARC 2
/* Intel Architecture */
#define EM_386 3
/* Motorola 68000 */
#define EM_68K 4
/* Motorola 88000 */
#define EM_88K 5
/* Intel 80860 */
#define EM_860 7
/* MIPS RS3000 Big-Endian */
#define EM_MIPS 8
/* MIPS RS4000 Big-Endian */
#define EM_MIPS_RS4_BE 10
/* PowerPC */
#define EM_PPC 20

/*=== Values for e_version ===*/
/* Invalid version */
#define EV_NONE 0
/* Current version */
#define EV_CURRENT 1

/*=== Special section indexes ===*/
/* Undefined, missing, irrelevant or meaningless */
#define SHN_UNDEF 0
/* Reserved */
#define SHN_LORESERVE 0xff00
/* Processor specific */
#define SHN_LOPROC 0xff00
/* Processor specific */
#define SHN_HIPROC 0xff1f
/* Absolute values */
#define SHN_ABS 0xfff1
/* Common symbols */
#define SHN_COMMON 0xfff2
/* Reserved */
#define SHN_HIRESERVE 0xffff

/*=== Section types ===*/
/* Inactive section */
#define SHT_NULL 0
/* Program defined information */
#define SHT_PROGBITS 1
/* Symbol table */
#define SHT_SYMTAB 2
/* String table */
#define SHT_STRTAB 3
/* Relocatable entries with explicit addends */
#define SHT_RELA 4
/* Symbol hash table */
#define SHT_HASH 5
/* Dynamic linking information */
#define SHT_DYNAMIC 6
/* Information that marks the file */
#define SHT_NOTE 7
/* Occupies no space in file */
#define SHT_NOBITS 8
/* Relocatable entries with no explicit addends */
#define SHT_REL 9
/* Reserved */
#define SHT_SHLIB 10
/* Dynamic symbol table */
#define SHT_DYNSYM 11
/* Processor specific */
#define SHT_LOPROC 0x70000000
/* Processor specific */
#define SHT_HIPROC 0x7fffffff
/* Application specific */
#define SHT_LOUSER 0x80000000
/* Application specific */
#define SHT_HIUSER 0xffffffff

/*=== Section flags ===*/
/* Writable */
#define SHF_WRITE 0x1
/* Occupies memory during process execution */
#define SHF_ALLOC 0x2
/* Executable */
#define SHF_EXECINSTR 0x4
/* Processor specific */
#define SHF_MASKPROC 0xf0000000

/*=== Symbol info bit manipulations ===*/
#define ELF32_ST_BIND(i) ((i)>>4)
#define ELF32_ST_TYPE(i) ((i)&0xf)
#define ELF32_ST_INFO(b,t) (((b)<<4)+((t)&0xf))

/*=== Symbol bindings ===*/
/* Local symbols */
#define STB_LOCAL 0
/* Global symbols */
#define STB_GLOBAL 1
/* Weak global symbols */
#define STB_WEAK 2
/* Processor specific */
#define STB_LOPROC 13
/* Processor specific */
#define STB_HIPROC 15

/*=== Symbol types ===*/
/* Type not specified */
#define STT_NOTYPE 0
/* Data object */
#define STT_OBJECT 1
/* Function or other executable code */
#define STT_FUNC 2
/* Symbol associated with a section */
#define STT_SECTION 3
/* */
#define STT_FILE 4
/* Processor specific */
#define STT_LOPROC 4
/* Processor specific */
#define STT_HIPROC 4

/*=== Relocation info bit manipulations ===*/
#define ELF32_R_SYM(i) ((i)>>8)
#define ELF32_R_TYPE(i) ((unsigned char)(i))
#define ELF32_R_INFO(s,t) (((s)<<8)+(unsigned char)(t))

/*=== Segment types ===*/
/* Ignored */
#define PT_NULL 0
/* Directly loaded to memory */
#define PT_LOAD 1
/* Dynamic linking information */
#define PT_DYNAMIC 2
/* Path to invoke an interpreter */
#define PT_INTERP 3
/* Auxiliary information */
#define PT_NOTE 4
/* Reserved */
#define PT_SHLIB 5
/* Specifies location and size of program header table */
#define PT_PHDR 6
/* Processor specific */
#define PT_LOPROC 0x70000000
/* Processor specific */
#define PT_HIPROC 0x7fffffff

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef struct
{
	unsigned char e_ident[EI_NIDENT];
	/* Object file type */
	Elf32_Half e_type;
	/* Required architecture */
	Elf32_Half e_machine;
	/* Object file format version */
	Elf32_Word e_version;
	/* Virtual address of first control transfer */
	Elf32_Addr e_entry;
	/* Program header table file offset */
	Elf32_Off e_phoff;
	/* Section header table file offset */
	Elf32_Off e_shoff;
	/* Processor specific flags */
	Elf32_Word e_flags;
	/* Header size */
	Elf32_Half e_ehsize;
	/* Program header table entry size */
	Elf32_Half e_phentsize;
	/* Program header table entry count */
	Elf32_Half e_phnum;
	/* Section header table entry size */
	Elf32_Half e_shentsize;
	/* Section header table entry count */
	Elf32_Half e_shnum;
	/* Index of section name string table inside section header table */
	Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct
{
	/* Section name, index into section header string table */
	Elf32_Word sh_name;
	/* Section type */
	Elf32_Word sh_type;
	/* Section flags */
	Elf32_Word sh_flags;
	/* Address of section in memory image */
	Elf32_Addr sh_addr;
	/* Section file offset */
	Elf32_Off sh_offset;
	/* Section size */
	Elf32_Word sh_size;
	/* Section header table index link */
	Elf32_Word sh_link;
	/* Extra information */
	Elf32_Word sh_info;
	/* Section address alignment */
	Elf32_Word sh_addralign;
	/* Entry size */
	Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct
{
	/* Symbol name, index into symbol string table */
	Elf32_Word st_name;
	/* Value of the symbol */
	Elf32_Addr st_value;
	/* Symbol size */
	Elf32_Word st_size;
	/* Symbol type and binding attributes */
	unsigned char st_info;
	/* No meaning, set to zero */
	unsigned char st_other;
	/* Related section header table index */
	Elf32_Half st_shndx;
} Elf32_Sym;

typedef struct
{
	/* Location of the relocation */
	Elf32_Addr r_offset;
	/* Symbol table index and relocation type */
	Elf32_Word r_info;
} Elf32_Rel;

typedef struct
{
	/* Location of the relocation */
	Elf32_Addr r_offset;
	/* Symbol table index and relocation type */
	Elf32_Word r_info;
	/* Constant offset from computed value */
	Elf32_Sword r_addend;
} Elf32_Rela;

typedef struct
{
	/* Segment type */
	Elf32_Word p_type;
	/* Segment file offset */
	Elf32_Off p_offset;
	/* Virtual address of segment */
	Elf32_Addr p_vaddr;
	/* Physical address of segment */
	Elf32_Addr p_paddr;
	/* Segment size in file */
	Elf32_Word p_filesz;
	/* Segment size in memory image */
	Elf32_Word p_memsz;
	/* Segment flags */
	Elf32_Word p_flags;
	/* Segment address alignment */
	Elf32_Word p_align;
} Elf32_Phdr;

#endif
