#ifndef MMU_DUMP_H_
#define MMU_DUMP_H_

#include <stdint.h>

//regs[16]
extern void sr_dump(uint32_t *regs);
extern uint32_t msr_dump();
//regs[16]
extern void bat_dump(uint32_t *regs);

#endif
