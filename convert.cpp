#include <map>
#include <string>
#include <stdexcept>
#include <set>
#include <vector>

#include "const.h"
#include "struct.h"

bool isReg(std::string &arg) {
    return registerMap.count(arg) == 1;
}

bool isReg64(std::string &reg) {
    return reg[0] == 'r';
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
    return { arg1, arg2 };
}

static std::tuple<std::string, char, std::string> splitMemAccess(std::string &mem) {
    std::string delim = mem.find('+') == std::string::npos ? " - " : " + ";

    auto base = mem.substr(mem.find('[') + 1, mem.find(delim) - mem.find('[') - 1);
    auto offset = mem.substr(mem.find(delim) + delim.length());
    offset.pop_back();

    return {base, delim[1], offset };
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
    if (op.length() == 3 && op[0] == 'j') // todo - perhaps more elegant
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
    return { convertArithmeticOp(instr, ADD) };
}

static std::vector<std::string> convertSubOp(cs_insn instr) {
    return { convertArithmeticOp(instr, SUB) };
}

static std::vector<std::string> generateMemAccess(std::string &arg, const std::string &dest) {
    auto [base, sign, offset] = splitMemAccess(arg);

    if (base == "rip") {
        std::string instr1 = "ldr " + convertReg(base) + ", #0";
        return {instr1};

        // todo - reloc

    } else {
        std::string instr1 = "mov " + tmp1_64 + ", " + (sign == '-' ? "-" : "") + offset;
        std::string instr2 = "ldr " + convertReg(dest) + ", [" + convertReg(base) + ", " + tmp1_64 + "]";
        return { instr1, instr2 };
    }
}

static std::vector<std::string> convertCmpOp(cs_insn instr) {
    auto [arg1, arg2] = splitArgs(instr);

    if (arg1.find('[') != std::string::npos) { // cmp mem, reg/imm
        auto code = generateMemAccess(arg1, tmp1_64);

        std::string newArg1 = getAppropriateTemp1Reg(arg2);
        std::string newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;

        code.emplace_back("cmp " + newArg1 + ", " + newArg2);
        return code;
    }

    if (arg2.find('[') != std::string::npos) { // cmp reg, mem
        auto code = generateMemAccess(arg2, tmp1_64);

        std::string newArg1 = convertReg(arg1);
        std::string newArg2 = getAppropriateTemp1Reg(arg1);

        code.emplace_back("cmp " + newArg1 + ", " + newArg2);
        return code;
    }

    // cmp reg, reg/imm
    std::string newArg1 = convertReg(arg1);
    std::string newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;
    return { "cmp " + newArg1 + ", " + newArg2 };
}

static std::vector<std::string> convertCallOp(cs_insn instr) {
    // todo - reloc
    return { "bl #0", "mov x9, x0" };
}

static std::vector<std::string> convertMovOp(cs_insn instr) {
    auto [arg1, arg2] = splitArgs(instr);

    if (arg1.find('[') != std::string::npos) { // mov mem, reg/imm
        auto [base, sign, offset] = splitMemAccess(arg1);

        if (base == "rip") {
            // todo - reloc

            auto tmp2 = getAppropriateTemp2Reg(arg2);

            return {
                "adr " + tmp1_64 + ", #0",
                "mov " + tmp2 + ", " + arg2,
                "str " + tmp2 + ", [" + tmp1_64 + "]"
            };

        } else {
            if (!isReg(arg2) /* && ma relokację */) {
                return {
                    "adr " + tmp1_64 + ", #0",
                    "mov " + tmp2_64 + ", " + offset,
                    "str " + tmp1_64 + ", [" + convertReg(base) + ", " + tmp2_64 + "]"
                    // todo - tmp1_64 w trzeciej linijce powinno byc pewnie jakims tam tmp1 (?)
                };
            }

            auto tmp1 = getAppropriateTemp1Reg(arg2);
            auto newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;

            return {
                "mov " + tmp1 + ", " + newArg2,
                "mov " + tmp2_64 + ", " + (sign == '-' ? "-" : "") + offset,
                "str " + tmp1 + ", [" + convertReg(base) + ", " + tmp2_64 + "]"
            };
        }

    }

    if (arg2.find('[') != std::string::npos) { // mov reg, mem
        return generateMemAccess(arg2, arg1);
    }

    // mov reg, reg/imm

    if (!isReg(arg2) /* && ma relokację */) { // todo - reloc
        arg1[0] = 'r';
        return { "adr " + convertReg(arg1) + ", #0" };
    }

    auto newArg2 = isReg(arg2) ? convertReg(arg2) : arg2;
    return { "mov " + convertReg(arg1) + ", " + newArg2 };
}

static std::vector<std::string> convertJmpOp(cs_insn instr, int offset) {
    return { "b " + std::to_string(offset) };
}

static std::vector<std::string> convertCondJmpOp(cs_insn instr, int offset) {
    std::string cond, mnemo;

    try {
        mnemo = std::string(instr.mnemonic);
        cond = conditionMap.at(mnemo.substr(1));
    } catch (std::exception &e) {
        throw std::runtime_error("conditional jump j" + mnemo + " not supported");
    }

    return { "b." + cond + " " + std::to_string(offset) };
}

std::vector<std::string> convertOp(cs_insn instr, int instrIndex, KeystoneWrapper &ks, std::map<int, int> &jumps) {
    InstrType type = getInstrType(instr);
    std::vector<std::string> code;

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
            code = convertCmpOp(instr);
            break;
        case CALL:
            code = convertCallOp(instr);
            break;
        case MOV:
            code = convertMovOp(instr);
            break;
        case JMP:
            code = convertJmpOp(instr, jumps[instrIndex]);
            break;
        case JMPCOND:
            code = convertCondJmpOp(instr, jumps[instrIndex]);
            break;
    }

    size_t size = 0;
    std::string mergedCode;

    for (auto &line : code) {
        mergedCode.append(line).append("; ");
    }

    unsigned char *encode;
    size_t curr_size = 0, count;

    // todo - address (currently 0)
    if (ks_asm(ks.handle, mergedCode.c_str(), 0, &encode, &size, &count)) {
        throw std::runtime_error("ks_asm failed on instruction " + mergedCode);
    }

    size += curr_size;
    ks_free(encode);

    return code;
}

std::map<int, int> getArmJumps(Assembly &code) {
    std::map<int, int> res{};

    for (int i = 0; i < code.count; i++) {
        auto currInstr = code.insn[i];

        if (std::string(currInstr.mnemonic) != "jmp") {
            continue;
        }

        int offset = std::stoi(std::string(currInstr.op_str));
        size_t destAddr = currInstr.address + offset;
        int j; // index of this jump's destination instruction

        for (j = 0; j < code.count; j++) {
            if (code.insn[j].address == destAddr) {
                break;
            }
        }

        if (j == code.count) {
            throw std::runtime_error("you dun fucked up !!! in: " + std::string(__FUNCTION__));
        }

        res.emplace(i, 4 * (j - i));
    }

    return res;
}

std::set<int> getCallIndexes(Assembly &code) {
    std::set<int> res{};

    for (int i = 0; i < code.count; i++) {
        auto currInstr = code.insn[i];

        if (std::string(currInstr.mnemonic) == "call") {
            res.insert(i);
        }
    }

    return res;
}
