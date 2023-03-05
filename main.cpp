#include <iostream>
#include <elf.h>
#include <fstream>
#include <array>
#include <vector>

#include "struct.h"
#include "convert.h"

class ElfConverter {

public:
    explicit ElfConverter(std::vector<char> &file) : file(file) {
        parseElfHeader();
        parseSectionHeaders();
        parseSymbols();
    }

    void convert(const char *path) {
        CapstoneWrapper capstone;
        KeystoneWrapper keystone;

        auto textSectionOffset = sectionHeaders[1].sh_offset;
        auto textSectionSize = sectionHeaders[1].sh_size;
        Assembly x86Code = disassemble(capstone.handle, textSectionOffset, textSectionSize);

        std::map<int, int> jumps = getArmJumps(x86Code);
        std::set<int> calls = getCallIndexes(x86Code);

        size_t currOffset = 0;
        std::vector<ArmCode> xArchCode{};

        std::cout << "\n\n\n"; // debug

        for (int i = 0; i < x86Code.count; i++) {
            cs_insn currInstr = x86Code.insn[i];
            InstrType type = getInstrType(currInstr);

            if (type == PROLOGUE) {
                i += x86Prologue.size() - 1;
            } else if (type == EPILOGUE) {
                i += x86Epilogue.size() - 1;
            }

            auto currOp = convertOp(currInstr, i, keystone, jumps);
            xArchCode.push_back(currOp);

            auto [code, size] = currOp;

            for (auto &str: code)
                std::cout << currOffset << "\t" << str << "\n";
            currOffset += size;
        }

        // todo -- handle offsets/sizes of instrs
    }

private:
    std::vector<char> file;
    Elf64_Ehdr elfHeader{};
    std::vector<Elf64_Shdr> sectionHeaders;
    std::vector<Elf64_Sym> symbols;

    void parseElfHeader() {
        std::copy_n(file.begin(), sizeof elfHeader, (char *) &elfHeader);
    }

    void parseSectionHeaders() {
        for (int i = 0; i < elfHeader.e_shnum; i++) {
            Elf64_Shdr header;

            auto offset = elfHeader.e_shoff + i * elfHeader.e_shentsize;
            std::copy_n(file.begin() + offset, elfHeader.e_shentsize, (char *) &header);

            sectionHeaders.push_back(header);
        }
    }

    void parseSymbols() {
        auto symbolSectionHeader = std::find_if(sectionHeaders.begin(), sectionHeaders.end(),
                                                [](Elf64_Shdr &hdr) { return hdr.sh_type == SHT_SYMTAB; });
        size_t base = symbolSectionHeader->sh_offset;
        size_t offset = 0;

        while (offset < symbolSectionHeader->sh_size) {
            Elf64_Sym symbol;

            std::copy_n(file.begin() + base + offset, sizeof symbol, (char *) &symbol);
            offset += sizeof symbol;

            symbols.push_back(symbol);
        }
    }

    // prob debug
    std::string getSectionName(size_t sectionIndex) {
        auto shstrtabPos = sectionHeaders[elfHeader.e_shstrndx].sh_offset;
        auto nameOffset = sectionHeaders[sectionIndex].sh_name;
        std::string res;

        for (size_t i = shstrtabPos + nameOffset; file[i] != '\0'; i++)
            res.push_back(file[i]);

        return res;
    }

    Assembly disassemble(csh &handle, size_t offset, size_t size) {
        cs_insn *insn;

        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(&file[offset]), size, 0, 0, &insn);

        if (count <= 0) {
            cs_close(&handle);
            throw std::runtime_error("decompilation failed");
        }

        // todo - debug
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
        }

        return {insn, count};
    }
};

std::ifstream readFile(const char *path) {
    std::ifstream handle(path, std::ifstream::binary);

    if (handle.fail()) {
        throw std::runtime_error("Could not open file");
    }

    return handle;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        throw std::runtime_error("Invalid argument count");
    }

    std::basic_ifstream<char> fileHandle = readFile(argv[1]);
    auto file = std::vector<char>(std::istreambuf_iterator<char>(fileHandle),
                                  std::istreambuf_iterator<char>());
    fileHandle.close();

    ElfConverter converter(file);
    converter.convert(argv[2]);

    std::cout << "File converted successfully\n";

    return 0;
}
