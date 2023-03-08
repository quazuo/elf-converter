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

std::vector<std::string> convertOp(cs_insn instr, int instrIndex, KeystoneWrapper &ks, std::map<int, int> &jumps);

std::map<int, int> getArmJumps(Assembly &code);

std::set<int> getCallIndexes(Assembly &code);

std::map<int, Elf64_Rela> getRelocIndexes(Assembly &code, std::vector<Elf64_Rela> &relocs);

#endif //CONVERTER_CONVERT_H
