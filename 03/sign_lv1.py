'''
调用SO中函数
'''

from unicorn import *
from unicorn.arm_const import *
import binascii


def hook_code(uc, address, size, userdata):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %
          (address, size))


def hook_memory(uc, access, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM_REG_PC)
    print("memory error: pc:%x address:%x size:%x" % (pc, address, size))


mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

# image
image_base = 0x0
image_size = 0x10000 * 8
mu.mem_map(image_base, image_size)
binary = open('libnative-lib.so', 'rb').read()
mu.mem_write(image_base, binary)  # 非常简陋的加载方法

# stack
stack_base = 0xa0000
stack_size = 0x10000 * 3
stack_top = stack_base + stack_size - 0x4
mu.mem_map(stack_base, stack_size)
mu.reg_write(UC_ARM_REG_SP, stack_top)

a1 = b'123'
# data segment
data_base = 0xf0000
data_size = 0x10000 * 3
mu.mem_map(data_base, data_size)
mu.mem_write(data_base, a1)
mu.reg_write(UC_ARM_REG_R0, data_base)

# set hook
mu.hook_add(UC_HOOK_CODE, hook_code, 0)
# mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_code, 0)
# mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_memory, 0)

# fix got table
# 应该为0，但是IDA查看有值是因为IDA自动分析填充了
mu.mem_write(0x1EDB0, b'\xD9\x98\x00\x00')


# start
target = image_base + 0x9B68
target_end = image_base + 0x9C2A
try:
    # THUMB2 指令可能是2字节，也可能是4字节 （通过PC的最低bit位来检测）
    # 在使用UNICORN模拟器 THUMB2 的时候，返回 UC_ERR_INSN_INVALID一定要检查当前设置PC值是不是正确
    # 会通过检测PC寄存器的最低bit 为0或者1来确定当前是属于THUMB模式还是ARM模式 然后设置当前环境的模式。
    # 所以如果是出于THUMB模式。一定要在PC上面+1。也就是说写PC寄存器的时候值应该为奇数。
    # uc_emu_start(uc, BASE + 0x12E2c + 1, BASE + 0x1BE64, 0, 0);
    # 虽然指令的起始地址为0x12E2c，并且处于THUMB模式，那么实际上PC应该写 0x12E2c | 1 (和+1是一样的)
    mu.emu_start(target+1, target_end)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    result = mu.mem_read(r2, 16)

    print(binascii.b2a_hex(result))

except UcError as e:
    print(e)
