#ifndef _RELOCATIONS_H_
#define _RELOCATIONS_H_

#define RELOCATE_WORD32(buff, addr) do { *(buff) = (addr); } while(0);
#define RELOCATE_WORD30(buff, addr) do { *(buff) = ((addr) << 2) | (*(buff) & 0x3); } while(0);
#define RELOCATE_LOW24(buff, addr)  do { *(buff) = (((addr) & 0xFFFFF) << 2) | (*(buff) & 0xF8000003); } while(0);
#define RELOCATE_LOW14(buff, addr)  do { *(buff) = (((addr) & 0x3FF) << 2) | (*(buff) & 0xFFFF0003); } while(0);
#define RELOCATE_HALF16(buff, addr) do { *(buff) = (addr) & 0xFFFF; } while(0);

#define ADDR_LO(addr) ((addr) & 0xFFFF)
#define ADDR_HI(addr) (((addr) >> 16) & 0xFFFF)
#define ADDR_HA(addr) ((((addr) >> 16) + ((addr) & 0x8000) ? 1 : 0) & 0xFFFF)

#define RELOCATE_ADDR32(buff, sym, addend)           do { RELOCATE_WORD32(buff, (sym) + (addend)); } while (0)
#define RELOCATE_ADDR24(buff, sym, addend)           do { RELOCATE_LOW24(buff, ((sym) + (addend)) >> 2); } while (0)
#define RELOCATE_ADDR16(buff, sym, addend)           do { RELOCATE_HALF16(buff, (sym) + (addend)); } while (0)
#define RELOCATE_ADDR16_LO(buff, sym, addend)        do { RELOCATE_HALF16(buff, ADDR_LO((sym) + (addend))); } while (0)
#define RELOCATE_ADDR16_HI(buff, sym, addend)        do { RELOCATE_HALF16(buff, ADDR_HI((sym) + (addend))); } while (0)
#define RELOCATE_ADDR16_HA(buff, sym, addend)        do { RELOCATE_HALF16(buff, ADDR_HA((sym) + (addend))); } while (0)
#define RELOCATE_ADDR14(buff, sym, addend)           do { RELOCATE_LOW14(buff, ((sym) + (addend)) >> 2); } while (0)
#define RELOCATE_ADDR14_BRTAKEN(buff, sym, addend)   do { RELOCATE_LOW14(buff, ((sym) + (addend)) >> 2); } while (0)
#define RELOCATE_ADDR14_BRNTAKEN(buff, sym, addend)  do { RELOCATE_LOW14(buff, ((sym) + (addend)) >> 2); } while (0)
#define RELOCATE_REL24(buff, sym, place, addend)            do { RELOCATE_LOW24(buff, ((sym) + (addend) - (place)) >> 2); } while (0)
#define RELOCATE_REL14(buff, sym, place, addend)            do { RELOCATE_LOW14(buff, ((sym) + (addend) - (place)) >> 2); } while (0)
#define RELOCATE_REL14_BRTAKEN(buff, sym, place, addend)    do { RELOCATE_LOW14(buff, ((sym) + (addend) - (place)) >> 2); } while (0)
#define RELOCATE_REL14_BRNTAKEN(buff, sym, place, addend)   do { RELOCATE_LOW14(buff, ((sym) + (addend) - (place)) >> 2); } while (0)
#define RELOCATE_GOT16(buff, got, addend)            do { RELOCATE_HALF16(buff, (got) + (addend)); } while (0)
#define RELOCATE_GOT16_LO(buff, got, addend)         do { RELOCATE_HALF16(buff, ADDR_LO((got) + (addend))); } while (0)
#define RELOCATE_GOT16_HI(buff, got, addend)         do { RELOCATE_HALF16(buff, ADDR_HI((got) + (addend))); } while (0)
#define RELOCATE_GOT16_HA(buff, got, addend)         do { RELOCATE_HALF16(buff, ADDR_HA((got) + (addend))); } while (0)
#define RELOCATE_PLTREL24(buff, plt, place, addend)  do { RELOCATE_LOW24(buff, (((plt) + (addend) - (place)) >> 2)); } while (0)
#define RELOCATE_COPY(buff)                          do { /* None */ } while (0)
#define RELOCATE_GLOB_DAT(buff, sym, addend)         do { RELOCATE_WORD32(buff, ((sym) + (addend))); } while (0)
#define RELOCATE_JMP_SLOT(buff)                      do { /* None */ } while (0)
#define RELOCATE_RELATIVE(buff, base, addend)        do { RELOCATE_WORD32(buff, (base) + (addend)); } while (0)
#define RELOCATE_LOCAL24PC(buff, base, addend)       do { RELOCATE_LOW24(buff, (base) + (addend)); } while (0)
#define RELOCATE_UADDR32(buff, sym, addend)          do { RELOCATE_WORD32(buff, (sym) + (addend)); } while (0)
#define RELOCATE_UADDR16(buff, sym, addend)          do { RELOCATE_HALF16(buff, (sym) + (addend)); } while (0)
#define RELOCATE_REL32(buff, sym, place, addend)     do { RELOCATE_WORD32(buff, (sym) + (addend) - (place)); } while (0)
#define RELOCATE_PLT32(buff, plt, addend)            do { RELOCATE_WORD32(buff, (plt) + (addend)); } while (0)
#define RELOCATE_PLTREL32(buff, plt, place, addend)  do { RELOCATE_WORD32(buff, (plt) + (addend) - (place)); } while (0)
#define RELOCATE_PLT16_LO(buff, plt, addend)         do { RELOCATE_HALF16(buff, ADDR_LO((plt) + (addend))); } while (0)
#define RELOCATE_PLT16_HI(buff, plt, addend)         do { RELOCATE_HALF16(buff, ADDR_HI((plt) + (addend))); } while (0)
#define RELOCATE_PLT16_HA(buff, plt, addend)         do { RELOCATE_HALF16(buff, ADDR_HA((plt) + (addend))); } while (0)
#define RELOCATE_SDAREL16(buff, sym, addend, sda)    do { RELOCATE_HALF16(buff, (sym) + (addend) - (sda)); } while (0)
#define RELOCATE_SECTOFF(buff, sectoff, addend)      do { RELOCATE_HALF16(buff, (sectoff) + (addend)); } while (0)
#define RELOCATE_SECTOFF_LO(buff, sectoff, addend)   do { RELOCATE_HALF16(buff, ADDR_LO((sectoff) + (addend))); } while (0)
#define RELOCATE_SECTOFF_HI(buff, sectoff, addend)   do { RELOCATE_HALF16(buff, ADDR_HI((sectoff) + (addend))); } while (0)
#define RELOCATE_SECTOFF_HA(buff, sectoff, addend)   do { RELOCATE_HALF16(buff, ADDR_HA((sectoff) + (addend))); } while (0)
#define RELOCATE_ADDR30(buff, sym, plt, addend)      do { RELOCATE_WORD30(buff, ((sym) + (addend) - (plt)) >> 2); } while (0)

#endif
