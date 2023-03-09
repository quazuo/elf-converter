#ifndef CONVERTER_CONVERT_H
#define CONVERTER_CONVERT_H

#include <map>
#include <string>
#include <set>

#include "const.h"
#include "struct.h"

bool isReg(std::string &arg);

bool isReg64(std::string &reg);

std::string convertReg(const std::string &reg);

std::string getAppropriateTemp1Reg(std::string &arg);

std::string getAppropriateTemp2Reg(std::string &arg);

enum InstrType {
    PROLOGUE, EPILOGUE, ADD, SUB, CMP, CALL, MOV, JMP, JMPCOND
};

InstrType getInstrType(cs_insn instr);

std::vector<std::string> convertOp(cs_insn instr, int instrIndex, std::map<int, int> &jumps);

CodeWithReloc convertOpWithReloc(cs_insn instr);

std::map<int, int> getArmJumps(Assembly &code, std::map<int, size_t> &relocIndexes, KeystoneWrapper &keystone);

std::set<int> getCallIndexes(Assembly &code);

std::map<int, size_t> getRelocIndexes(Assembly &code, std::vector<Elf64_Rela> &relocs);

#endif //CONVERTER_CONVERT_H
