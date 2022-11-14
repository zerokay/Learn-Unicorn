from unicorn import *
from unicorn.arm_const import *

from capstone import *
from capstone.arm import *

from UnicornTraceDebugger.udbg import UnicornDebugger

# mov r0, #0x37;
# sub r1, r2, r3
ARM_CODE = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"

print(">>> The simulated instructions are:")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for i in md.disasm(ARM_CODE, 0x1000):
    print("%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# Test ARM
# callback for tracing instructions


def hook_callback(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %
          (address, size))


def test_arm():
    print("Starting Emulate ARM Code ...")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 2MB memory for this emulation
        ADDRESS = 0x10000
        mu.mem_map(ADDRESS, 2 * 0x10000)
        mu.mem_write(ADDRESS, ARM_CODE)

        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)

        # mu.hook_add(UC_HOOK_CODE, hook_callback, begin=ADDRESS, end=ADDRESS)
        # mu.hook_add(UC_HOOK_CODE, hook_callback, begin=ADDRESS, end=ADDRESS + len(ARM_CODE))

        # debugger attach
        # udbg = UnicornDebugger(mu)
        # udbg.add_bpt(ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" % r0)
        print(">>> R1 = 0x%x" % r1)
    except UcError as e:
        print("ERROR: %s" % e)

test_arm()
