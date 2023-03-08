#include <iostream>
#include <elf.h>
#include <fstream>
#include <array>
#include <vector>
#include <cstring>
#include <iomanip>

#include "struct.h"
#include "convert.h"

class ElfConverter {

public:
    explicit ElfConverter(std::vector<uint8_t> &file) : file(file) {
        parseElfHeader();
        parseSectionHeaders();
        parseSymbols();
    }

    void convert(const char *path) {
        CapstoneWrapper capstone;
        KeystoneWrapper keystone;

        removeUselessSections();
        std::vector<uint8_t> newShstrtab = fixSectionNameTable();
        fixElfHeader();

        std::vector<uint8_t> newFile;
        newFile.insert(newFile.begin(), (uint8_t *) &elfHeader, (uint8_t *) &elfHeader + elfHeader.e_ehsize);

        size_t sectionsOffset = elfHeader.e_ehsize + sectionHeaders.size() * elfHeader.e_shentsize;
        size_t symtabOffset;

        // generate stub section headers that will be filled in later // todo -- fill it with headers
        newFile.resize(sectionsOffset);

        size_t currOffset = 0;
        for (auto &sec: sectionHeaders) {
            size_t currSize = 0;

            if (getSectionName(sec) == ".shstrtab") {
                newFile.insert(newFile.end(), newShstrtab.begin(), newShstrtab.end());
                currSize = newShstrtab.size();

            } else if (sec.sh_type == SHT_SYMTAB) {
                symtabOffset = currOffset;
                currSize = symbols.size() * sizeof(Elf64_Sym); // ??? todo make sure this sizeof works

            } else if (sec.sh_flags & SHF_EXECINSTR) {
                Assembly x86Code = disassemble(capstone.handle, sec.sh_offset, sec.sh_size);

                // get relocations data
                std::vector<Elf64_Rela> relocs = getRelocs(sec);
                std::map<int, Elf64_Rela> relocIndexes = getRelocIndexes(x86Code, relocs);
                std::vector<Elf64_Rela> newRelocs;

                // helper data
                std::map<int, int> jumps = getArmJumps(x86Code);
                std::set<int> calls = getCallIndexes(x86Code);

                size_t currInstrOffset = 0;
                std::vector<std::vector<std::string>> armCode{};

                for (int i = 0; i < x86Code.count; i++) {
                    cs_insn currInstr = x86Code.insn[i];
                    InstrType type = getInstrType(currInstr);

                    if (type == PROLOGUE) {
                        i += x86Prologue.size() - 1;
                    } else if (type == EPILOGUE) {
                        i += x86Epilogue.size() - 1;
                    }

                    auto currOp = convertOp(currInstr, i, keystone, jumps);
                    armCode.push_back(currOp);

                    for (auto &str: currOp) {
                        std::cout << currInstrOffset << "\t" << str << "\n";
                    }

                    if (relocIndexes.contains(i)) {
                        std::cout << "\t\t\t\t!RELOC! " << relocIndexes.at(i).r_offset << " " << currInstrOffset << "\n";
                    }

                    currInstrOffset += 4 * currOp.size();
                }

                // todo - dokonczyc

            } else {
                newFile.insert(newFile.end(), file.begin() + sec.sh_offset,
                               file.begin() + sec.sh_offset + sec.sh_size);
                currSize = sec.sh_size;
            }

            //...

            sec.sh_offset = currOffset;
            currOffset += currSize;
        }

        // todo - fill in symtab and section headers
    }

private:
    std::vector<uint8_t> file;
    Elf64_Ehdr elfHeader{};
    std::vector<Elf64_Shdr> sectionHeaders;
    std::vector<Elf64_Sym> symbols;

    std::vector<Elf64_Rela> getRelocs(Elf64_Shdr &section) {
        std::vector<Elf64_Rela> relocs;

        auto relocSectionName = ".rela" + getSectionName(section);
        auto relocSecHdr = std::find_if(sectionHeaders.begin(), sectionHeaders.end(),
                                        [relocSectionName, this](Elf64_Shdr &s) {
                                            return getSectionName(s) == relocSectionName;
                                        });

        auto base = relocSecHdr->sh_offset;
        auto offset = 0;

        while (offset < relocSecHdr->sh_size) {
            Elf64_Rela reloc;
            std::copy_n(file.begin() + base + offset, sizeof(Elf64_Rela), (uint8_t *) &reloc);
            relocs.push_back(reloc);
            offset += sizeof(Elf64_Rela);
        }

        return relocs;
    }

    void parseElfHeader() {
        std::copy_n(file.begin(), sizeof elfHeader, (uint8_t *) &elfHeader);
    }

    void fixElfHeader() {
        elfHeader.e_machine = EM_AARCH64;
        elfHeader.e_shoff = elfHeader.e_ehsize;

        auto shstrtabIter = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [this](Elf64_Shdr &sec) {
            return getSectionName(sec) == ".shstrtab";
        });

        elfHeader.e_shstrndx = std::distance(sectionHeaders.begin(), shstrtabIter);

        // debug
        for (int i = 0; i < elfHeader.e_ehsize / 16; i++) {
            for (int j = 0; j < 16; j += 2)
                std::cout
                    << std::setfill('0') << std::setw(2) << std::hex
                    << (int) *((uint8_t *) &elfHeader + 16 * i + j + 1)
                    << std::setfill('0') << std::setw(2) << std::hex
                    << (int) *((uint8_t *) &elfHeader + 16 * i + j)
                    << " ";
            std::cout << "\n";
        }
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
        auto base = symbolSectionHeader->sh_offset;
        auto offset = 0;

        while (offset < symbolSectionHeader->sh_size) {
            Elf64_Sym symbol;

            std::copy_n(file.begin() + base + offset, sizeof symbol, (char *) &symbol);
            offset += sizeof symbol;

            symbols.push_back(symbol);
        }
    }

    void removeUselessSections() {
        auto erasedCount = std::erase_if(sectionHeaders, [this](Elf64_Shdr &section) {
            return isUselessSectionName(getSectionName(section));
        });

        elfHeader.e_shnum -= erasedCount;

        // fix links in section headers
        size_t symtabIndex = 0;
        size_t strtabIndex = 0;

        while (sectionHeaders[symtabIndex].sh_type != SHT_SYMTAB) {
            symtabIndex++;
        }

        while (sectionHeaders[strtabIndex].sh_type != SHT_STRTAB) {
            strtabIndex++;
        }

        std::for_each(sectionHeaders.begin(), sectionHeaders.end(), [symtabIndex, strtabIndex](Elf64_Shdr &sec) {
            if (sec.sh_type == SHT_RELA) {
                sec.sh_link = symtabIndex;
            } else if (sec.sh_type == SHT_SYMTAB) {
                sec.sh_link = strtabIndex;
            }
        });
    }

    std::vector<uint8_t> fixSectionNameTable() {
        std::vector<uint8_t> res = {'\0'};

        auto shstrtab = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [this](Elf64_Shdr &sec) {
            return getSectionName(sec) == ".shstrtab";
        });

        auto offset = shstrtab->sh_offset;
        auto gluedNames = std::string(file.begin() + offset, file.begin() + offset + shstrtab->sh_size);

        for (size_t i = 1; i < shstrtab->sh_size;) {
            auto currName = std::string(gluedNames.c_str() + i); // trick to split on null characters

            if (!isUselessSectionName(currName)) {
                res.insert(res.end(), currName.begin(), currName.end());
                res.push_back('\0');
            }

            i += currName.length() + 1;
        }

        std::for_each(sectionHeaders.begin(), sectionHeaders.end(), [res, this](Elf64_Shdr &sec) {
            if (sec.sh_type == SHT_NULL) {
                return;
            }

            auto name = getSectionName(sec);
            auto it = std::search(res.begin(), res.end(), name.begin(), name.end());
            sec.sh_name = std::distance(res.begin(), it);
        });

        return res;
    }

    std::string getSectionName(Elf64_Shdr &section) {
        auto shstrtabPos = sectionHeaders[elfHeader.e_shstrndx].sh_offset;
        auto nameOffset = section.sh_name;
        std::string res;

        for (size_t i = shstrtabPos + nameOffset; file[i] != '\0'; i++)
            res.push_back(file[i]);

        return res;
    }

    static bool isUselessSectionName(const std::string &name) {
        return name == ".note.gnu.property" || name.ends_with(".eh_frame");
    };

    Assembly disassemble(csh &handle, size_t offset, size_t size) {
        cs_insn *insn;

        size_t count = cs_disasm(handle, &file[offset], size, 0, 0, &insn);

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
    auto file = std::vector<uint8_t>(std::istreambuf_iterator<char>(fileHandle),
                                     std::istreambuf_iterator<char>());
    fileHandle.close();

    ElfConverter converter(file);
    converter.convert(argv[2]);

    std::cout << "File converted successfully\n";

    return 0;
}
