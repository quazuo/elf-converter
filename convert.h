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

static std::pair<std::string, std::string> splitArgs(cs_insn instr);

static std::tuple<std::string, char, std::string> splitMemAccess(std::string &mem);

enum InstrType {
    PROLOGUE, EPILOGUE, ADD, SUB, CMP, CALL, MOV, JMP, JMPCOND
};

InstrType getInstrType(cs_insn instr);

static std::string convertArithmeticOp(cs_insn instr, InstrType type);

static std::vector<std::string> convertAddOp(cs_insn instr);

static std::vector<std::string> convertSubOp(cs_insn instr);

static std::vector<std::string> generateMemAccess(std::string &arg, const std::string &dest);

static std::vector<std::string> convertCmpOp(cs_insn instr);

static std::vector<std::string> convertCallOp(cs_insn instr);

static std::vector<std::string> convertMovOp(cs_insn instr);

static std::vector<std::string> convertJmpOp(cs_insn instr, int offset);

static std::vector<std::string> convertCondJmpOp(cs_insn instr, int offset);

std::vector<std::string> convertOp(cs_insn instr, int instrIndex, KeystoneWrapper &ks, std::map<int, int> &jumps);

std::map<int, int> getArmJumps(Assembly &code);

std::set<int> getCallIndexes(Assembly &code);

#endif //CONVERTER_CONVERT_H
