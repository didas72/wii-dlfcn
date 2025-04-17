	.global sr_dump
	.global msr_dump
	.global bat_dump
	.text

# void sr_dump(uint32_t regs[16])
# r3 <= regs
# r4 = buffer
sr_dump:
	mfsr 4, 0   # r4 <- SR0
	stw 4, 0(3) # regs[0] <- r4
	mfsr 4, 1   # r4 <- SR1
	stw 4, 4(3) # regs[1] <- r4
	mfsr 4, 2
	stw 4, 8(3)
	mfsr 4, 3
	stw 4, 12(3)
	mfsr 4, 4
	stw 4, 16(3)
	mfsr 4, 5
	stw 4, 20(3)
	mfsr 4, 6
	stw 4, 24(3)
	mfsr 4, 7
	stw 4, 28(3)
	mfsr 4, 8
	stw 4, 32(3)
	mfsr 4, 9
	stw 4, 36(3)
	mfsr 4, 10
	stw 4, 40(3)
	mfsr 4, 11
	stw 4, 44(3)
	mfsr 4, 12
	stw 4, 48(3)
	mfsr 4, 13
	stw 4, 52(3)
	mfsr 4, 14
	stw 4, 56(3)
	mfsr 4, 15
	stw 4, 60(3)
	blr # ret

# uint32_t msr_dump()
# r3 => msr
msr_dump:
	mfmsr 3 # r3 <- msr
	blr # ret

# void bat_dump(uint32_t regs[16])
# r3 <= regs
# r4 - buffer
bat_dump:
	mfspr 4, 537 # r4 <- DBAT0L
	stw 4, 0(3)  # regs[0] <- r4
	mfspr 4, 536 # r4 <- DBAT0U
	stw 4, 4(3)  # regs[1] <- r4
	mfspr 4, 539 # r4 <- DBAT1L
	stw 4, 8(3)  # regs[2] <- r4
	mfspr 4, 538 # r4 <- DBAT1U
	stw 4, 12(3)  # regs[3] <- r4
	mfspr 4, 541 # r4 <- DBAT2L
	stw 4, 16(3)  # regs[4] <- r4
	mfspr 4, 540 # r4 <- DBAT2U
	stw 4, 20(3)  # regs[5] <- r4
	mfspr 4, 541 # r4 <- DBAT3L
	stw 4, 24(3)  # regs[6] <- r4
	mfspr 4, 540 # r4 <- DBAT3U
	stw 4, 28(3)  # regs[7] <- r4

	mfspr 4, 529 # r4 <- IBAT0L
	stw 4, 32(3)  # regs[8] <- r4
	mfspr 4, 528 # r4 <- IBAT0U
	stw 4, 36(3)  # regs[9] <- r4
	mfspr 4, 531 # r4 <- IBAT1L
	stw 4, 40(3)  # regs[10] <- r4
	mfspr 4, 530 # r4 <- IBAT1U
	stw 4, 44(3)  # regs[11] <- r4
	mfspr 4, 533 # r4 <- IBAT2L
	stw 4, 48(3)  # regs[12] <- r4
	mfspr 4, 532 # r4 <- IBAT2U
	stw 4, 52(3)  # regs[13] <- r4
	mfspr 4, 535 # r4 <- IBAT3L
	stw 4, 56(3)  # regs[14] <- r4
	mfspr 4, 534 # r4 <- IBAT3U
	stw 4, 60(3)  # regs[15] <- r4

	blr # ret
