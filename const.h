#ifndef CONVERTER_CONST_H
#define CONVERTER_CONST_H

#include <map>
#include <string>

const std::map<std::string, std::string> registerMap = {
    {"rdi", "x0"},
    {"edi", "w0"},
    {"rsi", "x1"},
    {"esi", "w1"},
    {"rdx", "x2"},
    {"edx", "w2"},
    {"rcx", "x3"},
    {"ecx", "w3"},
    {"r8",  "x4"},
    {"r8d",  "w4"},
    {"r9",  "x5"},
    {"r9d",  "w5"},
    {"rax", "x9"},
    {"eax", "w9"},
    {"r10", "x10"},
    {"e10", "w10"},
    {"r11", "x11"},
    {"r11d", "w11"},
    {"rbp", "x29"},
    {"ebp", "w29"},
    {"rbx", "x19"},
    {"ebx", "w19"},
    {"r12", "x20"},
    {"r12d", "w20"},
    {"r13", "x21"},
    {"r13d", "w21"},
    {"r14", "x22"},
    {"r14d", "w22"},
    {"r15", "x23"},
    {"r15d", "w23"},
    {"rsp", "sp"},
};

const std::string tmp1_32 = "w12";
const std::string tmp1_64 = "x12";
const std::string tmp2_32 = "w13";
const std::string tmp2_64 = "x13";

const std::vector<std::string> x86Prologue = {
    "endbr64",
    "push rbp",
    "mov rbp, rsp",
};

const std::vector<std::string> x86Epilogue = {
    "leave",
    "ret",
};

const std::vector<std::string> armPrologue = {
    "stp x29, x30, [sp, #-16]!",
    "mov x29, sp",
};

const std::vector<std::string> armEpilogue = {
    "mov x0, x9",
    "add sp, x29, #16",
    "ldp x29, x30, [sp, #-16]",
    "ret",
};

const std::map<std::string, std::string> conditionMap = {
    {"a",   "hi"},
    {"ae",  "hs"},
    {"b",   "lo"},
    {"be",  "ls"},
    {"c",   "cs"},
    {"e",   "eq"},
    {"g",   "gt"},
    {"ge",  "ge"},
    {"l",   "lt"},
    {"le",  "le"},
    {"na",  "ls"},
    {"nae", "lo"},
    {"nb",  "hs"},
    {"nbe", "hi"},
    {"nc",  "cc"},
    {"ne",  "ne"},
    {"ng",  "le"},
    {"nge", "lt"},
    {"nl",  "ge"},
    {"nle", "gt"},
    {"no",  "vc"},
    {"nz",  "ne"},
    {"o",   "vs"},
    {"z",   "eq"},
};


#endif //CONVERTER_CONST_H
