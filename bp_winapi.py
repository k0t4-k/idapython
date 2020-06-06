#!/usr/bin/python

import idc
import idautils

func_list = [
    "kernelbase_VirtualAlloc",
    "kernelbase_VirtualProtect",
    "kernel32_CreateThread",
    "kernelbase_CreateProcessA",
    "kernelbase_CreateProcessInternalA"
    "kernelbase_CreateProcessW",
    "kernelbase_CreateProcessAsUserW",
    "kernel32_FindResourceA",
    "kernelbase_LoadResource",
]

if __name__ == "__main__":
    for func in func_list:
        func_addr = idc.LocByName(func)
        print "Set BreakPoint: %X, %s" % (func_addr, func)
        idc.add_bpt(func_addr, 0, BPT_SOFT)
        idc.enable_bpt(func_addr, True)