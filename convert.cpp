#include <map>
#include <string>
#include <stdexcept>
#include <set>
#include <vector>
#include <elf.h>
#include <functional>
#include <iostream>
#include <sstream>

#include "const.h"
#include "struct.h"

bool isReg(const std::string &arg) {
    return registerMap.count(arg) == 1;
}

bool isReg64(const std::string &reg) {
    return reg[0] == 'r';
}

std::string regTo64(const std::string &reg) {
    if (reg.ends_with('d')) {
        return reg.substr(0, reg.length() - 1);
    }

    std::string ret = reg;
    ret[0] = 'r';
    return ret;
}

std::string convertReg(const std::string &reg) {
    std::string res;

    try {
        res = registerMap.at(reg);
    } catch (std::exception &e) {
        throw std::runtime_error("register " + reg + " not supported");
    }

    return res;
}

std::string getAppropriateTemp1Reg(std::string &arg) {
    bool isArg64 = !isReg(arg) || isReg64(arg);
    return isArg64 ? tmp1_64 : tmp1_32;
}

std::string getAppropriateTemp2Reg(std::string &arg) {
    bool isArg64 = !isReg(arg) || isReg64(arg);
    return isArg64 ? tmp2_64 : tmp2_32;
}

static std::pair<std::string, std::string> splitArgs(cs_insn instr) {
    std::string args = instr.op_str;
    std::string delim = ", ";
    auto arg1 = args.substr(0, args.find(delim));
    auto arg2 = args.substr(args.find(delim) + delim.length());
    return {arg1, arg2};
}

static std::tuple<std::string, char, std::string> splitMemAccess(std::string &mem) {
    if (mem.find('+') == std::string::npos && mem.find('-') == std::string::npos) {
        std::string base = mem.substr(mem.find('[') + 1);
        base.erase(base.find(']'));

        return {base, '+', "0"};
    }

    std::string delim = mem.find('+') == std::string::npos ? " - " : " + ";

    auto base = mem.substr(mem.find('[') + 1, mem.find(delim) - mem.find('[') - 1);
    auto offset = mem.substr(mem.find(delim) + delim.length());
    offset.pop_back();

    return {base, delim[1], offset};
}

enum InstrType {
    PROLOGUE, EPILOGUE, ADD, SUB, CMP, CALL, MOV, JMP, JMPCOND
};

InstrType getInstrType(cs_insn instr) {
    auto op = std::string(instr.mnemonic);

    if (op == x86Prologue[0])
        return PROLOGUE;
    if (op == x86Epilogue[0])
        return EPILOGUE;
    if (op == "add")
        return ADD;
    if (op == "sub")
        return SUB;
    if (op == "cmp")
        return CMP;
    if (op == "call")
        return CALL;
    if (op == "mov")
        return MOV;
    if (op == "jmp")
        return JMP;
    if (op.length() <= 3 && op[0] == 'j') // todo - perhaps more elegant
        return JMPCOND;

    throw std::runtime_error("instruction " + op + " not supported");
}

static std::string convertArithmeticOp(cs_insn instr, InstrType type) {
    std::string args = instr.op_str;
    std::string delim = ", ";
    std::string arg1 = args.substr(0, args.find(delim));
    std::string arg2 = args.substr(args.find(delim) + delim.length());

    std::string newArg1 = convertReg(arg1);
    std::string newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;

    std::string mnemo;

    switch (type) {
        case ADD:
            mnemo = "add";
            break;
        case SUB:
            mnemo = "sub";
            break;
        default:
            throw std::runtime_error("invalid instr type in " + std::string(__FUNCTION__));
    }

    return mnemo + " " + newArg1 + ", " + newArg1 + ", " + newArg2;
}

static std::vector<std::string> convertAddOp(cs_insn instr) {
    return {convertArithmeticOp(instr, ADD)};
}

static std::vector<std::string> convertSubOp(cs_insn instr) {
    return {convertArithmeticOp(instr, SUB)};
}

static CodeWithReloc generateMemAccess(std::string &src, const std::string &dest) {
    auto [base, sign, offset] = splitMemAccess(src);

    if (base == "rip") {
        std::string instr1 = "ldr " + convertReg(dest) + ", #0";
        return {{instr1}, R_AARCH64_LD_PREL_LO19};
    }

    auto newDest = isReg(dest) ? convertReg(dest) : dest;
    std::string instr1 = "mov " + tmp1_64 + ", " + (sign == '-' ? "-" : "") + offset;
    std::string instr2 = "ldr " + newDest + ", [" + convertReg(base) + ", " + tmp1_64 + "]";
    return {{instr1, instr2}, R_AARCH64_NONE};
}

static CodeWithReloc convertCmpOp(cs_insn instr) {
    auto [arg1, arg2] = splitArgs(instr);

    if (arg1.find('[') != std::string::npos) { // cmp mem, reg/imm
        std::string temp1 = getAppropriateTemp1Reg(arg2);
        auto [code, reloc] = generateMemAccess(arg1, temp1);
        std::string newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;

        code.emplace_back("cmp " + temp1 + ", " + newArg2);
        return {code, reloc};
    }

    if (arg2.find('[') != std::string::npos) { // cmp reg, mem
        auto [code, reloc] = generateMemAccess(arg2, tmp1_64);

        std::string newArg1 = convertReg(arg1);
        std::string newArg2 = getAppropriateTemp1Reg(arg1);

        code.emplace_back("cmp " + newArg1 + ", " + newArg2);
        return {code, reloc};
    }

    // cmp reg, reg/imm
    std::string newArg1 = convertReg(arg1);
    std::string newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;
    return {
        {"cmp " + newArg1 + ", " + newArg2},
        R_AARCH64_NONE
    };
}

static CodeWithReloc convertCallOp(cs_insn instr) {
    return {
        {"bl #0", "mov x9, x0"},
        R_AARCH64_CALL26
    };
}

static CodeWithReloc convertMovOp(cs_insn instr, bool withReloc) {
    auto [arg1, arg2] = splitArgs(instr);

    if (arg1.find('[') != std::string::npos) { // mov mem, reg/imm
        auto [base, sign, offset] = splitMemAccess(arg1);

        if (base == "rip") {
            auto tmp2 = getAppropriateTemp2Reg(arg2);

            return {
                {
                    "adr " + tmp1_64 + ", #0",
                    "mov " + tmp2 + ", " + arg2,
                    "str " + tmp2 + ", [" + tmp1_64 + "]"
                },
                R_AARCH64_ADR_PREL_LO21
            };

        } else {
            if (!isReg(arg2) && withReloc) {
                return {
                    {
                        "adr " + tmp1_64 + ", #0",
                        "mov " + tmp2_64 + ", " + offset,
                        "str " + tmp1_64 + ", [" + convertReg(base) + ", " + tmp2_64 + "]"
                        // todo - tmp1_64 w trzeciej linijce powinno byc pewnie jakims tam tmp1 (?)
                    },
                    R_AARCH64_ADR_PREL_LO21
                };
            }

            auto tmp1 = getAppropriateTemp1Reg(arg2);
            auto newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;

            return {
                {
                    "mov " + tmp1 + ", " + newArg2,
                    "mov " + tmp2_64 + ", " + (sign == '-' ? "-" : "") + offset,
                    "str " + tmp1 + ", [" + convertReg(base) + ", " + tmp2_64 + "]"
                },
                R_AARCH64_NONE
            };
        }
    }

    if (arg2.find('[') != std::string::npos) { // mov reg, mem
        return generateMemAccess(arg2, arg1);
    }

    // mov reg, reg/imm

    if (!isReg(arg2) && withReloc) {
        auto arg1_64 = regTo64(arg1);
        return {
            {"adr " + convertReg(arg1_64) + ", #0"},
            R_AARCH64_ADR_PREL_LO21
        };
    }

    auto newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;
    return {
        {"mov " + convertReg(arg1) + ", " + newArg2},
        R_AARCH64_NONE
    };
}

static std::vector<std::string> convertJmpOp(cs_insn instr, int offset) {
    return {"b " + std::to_string(offset)};
}

static std::vector<std::string> convertCondJmpOp(cs_insn instr, int offset) {
    std::string cond, mnemo;

    try {
        mnemo = std::string(instr.mnemonic);
        cond = conditionMap.at(mnemo.substr(1));
    } catch (std::exception &e) {
        throw std::runtime_error("conditional jump with mnemo: " + mnemo + "and cond: " + cond + " not supported");
    }

    return {"b." + cond + " " + std::to_string(offset)};
}

std::vector<std::string> convertOp(cs_insn instr, int instrIndex, std::map<int, int> &jumps) {
    InstrType type = getInstrType(instr);
    std::vector<std::string> code;
    CodeWithReloc codeWithReloc;

    switch (type) {
        case PROLOGUE:
            code = armPrologue;
            break;
        case EPILOGUE:
            code = armEpilogue;
            break;
        case ADD:
            code = convertAddOp(instr);
            break;
        case SUB:
            code = convertSubOp(instr);
            break;
        case CMP:
            codeWithReloc = convertCmpOp(instr);
            code = codeWithReloc.first;
            break;
        case CALL:
            codeWithReloc = convertCallOp(instr);
            code = codeWithReloc.first;
            break;
        case MOV:
            codeWithReloc = convertMovOp(instr, false);
            code = codeWithReloc.first;
            break;
        case JMP:
            code = convertJmpOp(instr, jumps[instrIndex]);
            break;
        case JMPCOND:
            code = convertCondJmpOp(instr, jumps[instrIndex]);
            break;
    }

    return code;
}

CodeWithReloc convertOpWithReloc(cs_insn instr) {
    InstrType type = getInstrType(instr);
    CodeWithReloc codeWithReloc;

    switch (type) {
        case CMP:
            codeWithReloc = convertCmpOp(instr);
            break;
        case CALL:
            codeWithReloc = convertCallOp(instr);
            break;
        case MOV:
            codeWithReloc = convertMovOp(instr, true);
            break;
        default:
            throw std::runtime_error("unexpected operation in " + std::string(__FUNCTION__));
    }

    return codeWithReloc;
}

std::map<int, int> getArmJumps(Assembly &code, std::map<int, size_t> &relocIndexes, KeystoneWrapper &keystone) {
    std::map<int, int> res{};

    std::map<int, int> dummyJumps; // for convertOp
    std::map<int, int> instrIndexMapping; // (index of x86 instruction) -> (index of arm instruction)
    int currSize = 0;

    for (int i = 0; i < code.count; i++) {
        cs_insn currInstr = code.insn[i];
        InstrType type = getInstrType(currInstr);

        instrIndexMapping.emplace(i, currSize);

        std::vector<std::string> currCode;

        if (relocIndexes.contains(i)) {
            auto codeWithReloc = convertOpWithReloc(currInstr);
            currCode = codeWithReloc.first;
        } else {
            currCode = convertOp(currInstr, i, dummyJumps);
        }

        if (type == PROLOGUE) {
            i += x86Prologue.size() - 1;

        } else if (type == EPILOGUE) {
            i += x86Epilogue.size() - 1;
        }

        currSize += currCode.size();
    }

    for (int i = 0; i < code.count; i++) {
        auto currInstr = code.insn[i];

        if (currInstr.mnemonic[0] != 'j') {
            continue;
        }

        int dest;
        std::stringstream ss;
        ss << std::hex << currInstr.op_str;
        ss >> dest;

        int j = 0; // index of this jump's destination instruction

        while (code.insn[j].address != dest) {
            j++;
        }

        if (j == code.count) {
            throw std::runtime_error("you dun fucked up !!! in: " + std::string(__FUNCTION__));
        }

        res.emplace(i, 4 * (instrIndexMapping.at(j)));
    }

    return res;
}

std::set<int> getCallIndexes(Assembly &code) {
    std::set<int> res;

    for (int i = 0; i < code.count; i++) {
        auto currInstr = code.insn[i];

        if (std::string(currInstr.mnemonic) == "call") {
            res.insert(i);
        }
    }

    return res;
}

std::map<int, size_t> getRelocIndexes(Assembly &code, std::vector<Elf64_Rela> &relocs) {
    std::map<int, size_t> res;

    for (int i = 0; i < code.count; i++) {
        cs_insn currInstr = code.insn[i];

        if (i < code.count - 1) {
            cs_insn nextInstr = code.insn[i + 1];

            auto reloc = std::find_if(relocs.begin(), relocs.end(), [currInstr, nextInstr](Elf64_Rela &reloc) {
                return reloc.r_offset >= currInstr.address && reloc.r_offset < nextInstr.address;
            });

            if (reloc != relocs.end()) {
                res[i] = std::distance(relocs.begin(), reloc);
            }

        } else {
            auto reloc = std::find_if(relocs.begin(), relocs.end(), [currInstr](Elf64_Rela &reloc) {
                return reloc.r_offset >= currInstr.address;
            });

            if (reloc != relocs.end()) {
                res[i] = std::distance(relocs.begin(), reloc);
            }
        }
    }

    return res;
}
