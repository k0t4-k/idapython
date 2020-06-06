#!/usr/bin/python

from idautils import *
from idc import *

operand = ["and", "or", "shr", "shl"]

def check_operand_count(dism_addr):
    count = 0
    for line in dism_addr:
        if GetMnem(line) in operand:
            count += 1
        
    if count >= 5:
        print "Function with many opcodes used for encryption: %s" % GetFunctionName(dism_addr[0])

def check_encode_by_xor(dism_addr):
    for line in dism_addr:
        if GetMnem(line) == "xor": 
            operand1 = GetOpnd(line, 0)
            operand2 = GetOpnd(line, 1)
            if operand1 and operand2 and operand1 != operand2 and operand2 != "ebp":
                print "Function performing encoding by xor opcode: %s, %X" % (GetFunctionName(dism_addr[0]), line)
                break


if __name__ == "__main__":
    print "[*] Start"
    for func in idautils.Functions():
        if not "sub" in GetFunctionName(func):
            continue

        dism_addr = list(FuncItems(func))
        check_operand_count(dism_addr)
        check_encode_by_xor(dism_addr)

    print "[*] Done"
