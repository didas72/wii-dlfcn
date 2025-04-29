# wii-dlfcn

`wii-dlfcn` is a POSIX `dlfcn`-like interface to dynamically load binaries, tailor-made for the Nintento Wii.
While not strictly POSIX compliant (see notes below), it provides a similar enough interface that should feel familiar to those who have used the 'proper' one.

## Target platform

This code is meant to run on the Wii (PowerPC). Specifically, it is meant to be used with [libogc](https://github.com/devkitPro/libogc/) and [devkitPro](https://devkitpro.org/) tools.

## Limitations and diferences to POSIX

Given the limitations of running 'bare metal' PowerPC code, certain features required by POSIX might not be made available or their behaviours may differ, at least until I figure out a way to cleanly implement them. For example:

- An initialization function call will be required

These limitations are not fully figured out, as the project is still very early into development.

## Unprepared notes for users

This section is for notes that I need to leave to users but have not been properly written just yet. It serves mostly as a documentation TODO list.

- `.o` files only (ELF relocatables)
- Build with `-fno-pic -ffreestanding -nostdlib -fno-function-sections -fno-data-sections`
- Partially link with `ld -r` to merge objects
- All dependencies of loaded `.o` must be present in running `.elf`
- No linking `.o` against other `.o` for now
