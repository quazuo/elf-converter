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

        // save reloc tables for later
        std::map<size_t, std::vector<Elf64_Rela>> newRelocTables;

        // generate stub section headers that will be filled in later
        newFile.resize(sectionsOffset);

        size_t currOffset = 0;

        for (auto &sec: sectionHeaders) {
            size_t currSize = 0;

            auto alignedOffset = alignOffset(currOffset, sec.sh_addralign);

            if (alignedOffset != currOffset) {
                newFile.resize(newFile.size() + alignedOffset - currOffset);
                currOffset = alignedOffset;
            }

            if (getSectionName(sec) == ".shstrtab") {
                newFile.insert(newFile.end(), newShstrtab.begin(), newShstrtab.end());
                currSize = newShstrtab.size();

            } else if (sec.sh_type == SHT_SYMTAB) {
                symtabOffset = sectionsOffset + currOffset;
                currSize = symbols.size() * sizeof(Elf64_Sym);
                newFile.resize(newFile.size() + currSize);

            } else if (sec.sh_flags & SHF_EXECINSTR) {
                Assembly x86Code = disassemble(capstone.handle, sec.sh_offset, sec.sh_size);

                // get relocations data
                Elf64_Shdr relocsHeader = getRelocSecHdr(sec);
                std::vector<Elf64_Rela> relocs = getRelocs(relocsHeader);
                std::map<int, size_t> relocIndexes = getRelocIndexes(x86Code, relocs); // indexOfInstr -> indexOfReloc

                // helper data
                std::map<int, int> jumps = getArmJumps(x86Code, relocIndexes, keystone);
                std::set<int> calls = getCallIndexes(x86Code);

                size_t currInstrOffset = 0;
                size_t currFuncSize = 0, currFuncSymbolIndex;
                std::vector<std::vector<std::string>> armCode{};

                for (int i = 0; i < x86Code.count; i++) {
                    cs_insn currInstr = x86Code.insn[i];
                    InstrType type = getInstrType(currInstr);

                    if (type == PROLOGUE) {
                        currFuncSize = 0;
                        currFuncSymbolIndex = getFuncSymbolIndex(sec, currInstr.address);
                        symbols[currFuncSymbolIndex].st_value = currInstrOffset;
                        i += x86Prologue.size() - 1;

                    } else if (type == EPILOGUE) {
                        symbols[currFuncSymbolIndex].st_size = currFuncSize + armEpilogue.size() * 4;
                        i += x86Epilogue.size() - 1;
                    }

                    std::vector<std::string> currCode;

                    if (relocIndexes.contains(i)) {
                        auto codeWithReloc = convertOpWithReloc(currInstr, currInstrOffset);
                        currCode = codeWithReloc.first;
                        auto currRelocType = codeWithReloc.second;
                        Elf64_Rela *currReloc = &relocs[relocIndexes.at(i)];

                        currReloc->r_info = ELF64_R_INFO(ELF64_R_SYM(currReloc->r_info), currRelocType);
                        currReloc->r_offset = currInstrOffset;

                        // fix addend
                        std::string args = currInstr.op_str;
                        const char *key = "rip";
                        auto iter = std::search(args.begin(), args.end(), key, key + strlen(key));
                        bool isRipAddressed = iter != args.end();

                        if (currRelocType == R_AARCH64_CALL26 || isRipAddressed) {
                            currReloc->r_addend += 4;
                        }

                    } else {
                        currCode = convertOp(currInstr, i, currInstrOffset, jumps);
                    }

                    armCode.push_back(currCode);

                    currInstrOffset += 4 * currCode.size();
                    currFuncSize += 4 * currCode.size();
                }

                std::vector<char> armAssembly = compileArmCode(armCode, keystone);
                newFile.insert(newFile.end(), armAssembly.begin(), armAssembly.end());
                currSize = armAssembly.size();

                if (!relocs.empty()) {
                    auto relocTableOffset = alignOffset(sectionsOffset + currOffset + currSize,
                                                        relocsHeader.sh_addralign);
                    newRelocTables.emplace(relocTableOffset, relocs);
                }

            } else if (sec.sh_type == SHT_RELA && !(sectionHeaders[sec.sh_info].sh_flags & SHF_EXECINSTR)) {
                std::vector<Elf64_Rela> relocs = getRelocs(sec);

                for (auto &reloc: relocs) {
                    reloc.r_info = ELF64_R_INFO(ELF64_R_SYM(reloc.r_info), R_AARCH64_ABS64);
                }

                newRelocTables.emplace(sectionsOffset + currOffset, relocs);
                currSize = sec.sh_size;
                newFile.resize(newFile.size() + currSize);

            } else if (sec.sh_type == SHT_NOBITS) {
                sec.sh_offset = sectionsOffset + currOffset;
                continue;

            } else {
                newFile.insert(newFile.end(), file.begin() + sec.sh_offset,
                               file.begin() + sec.sh_offset + sec.sh_size);
                currSize = sec.sh_size;
            }

            sec.sh_offset = sectionsOffset + currOffset;
            sec.sh_size = currSize;
            currOffset += currSize;
        }

        // reloc sections!
        for (auto &[pos, relocTable]: newRelocTables) {
            size_t offset = 0;

            for (auto &reloc: relocTable) {
                std::copy_n((uint8_t *) &reloc, sizeof reloc, newFile.begin() + pos + offset);
                offset += sizeof reloc;
            }
        }

        // symtab section!
        size_t offset = 0;

        for (auto &sym: symbols) {
            std::copy_n((uint8_t *) &sym, sizeof sym, newFile.begin() + symtabOffset + offset);
            offset += sizeof sym;
        }

        // section headers!
        offset = 0;

        for (auto &header: sectionHeaders) {
            std::copy_n((uint8_t *) &header, sizeof header, newFile.begin() + elfHeader.e_ehsize + offset);
            offset += sizeof header;
        }

        // emit file
        std::ofstream handle(path, std::ios::binary);

        if (handle.fail()) {
            throw std::runtime_error("Could not open file");
        }

        for (auto c: newFile) {
            handle << c;
        }

        handle.close();
    }

private:
    std::vector<uint8_t> file;
    Elf64_Ehdr elfHeader{};
    std::vector<Elf64_Shdr> sectionHeaders;
    std::vector<Elf64_Sym> symbols;

    // parsing

    void parseElfHeader() {
        std::copy_n(file.begin(), sizeof elfHeader, (uint8_t *) &elfHeader);
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

    // conversion

    void removeUselessSections() {
        // remove references to useless sections in the symbol table

//        std::erase_if(symbols, [this](Elf64_Sym &sym) {
//            if (ELF64_ST_TYPE(sym.st_info) != STT_SECTION) {
//                return false;
//            }
//
//            std::string name = getSectionName(sectionHeaders[sym.st_shndx]);
//            return isUselessSectionName(name);
//        });
//
        // remember which sections were linked to sections with which names

        std::map<int, std::string> symbolSecNames;

        for (int i = 0; i < symbols.size(); i++) {
            const auto sym = symbols[i];

            if (sym.st_shndx > 0 && sym.st_shndx < sectionHeaders.size()) {
                std::string name = getSectionName(sectionHeaders[sym.st_shndx]);
                symbolSecNames.emplace(i, name);
            }
        }

        // remove the sections

        auto erasedCount = std::erase_if(sectionHeaders, [this](Elf64_Shdr &section) {
            return isUselessSectionName(getSectionName(section));
        });

        elfHeader.e_shnum -= erasedCount;

        // fix links in section headers

        size_t symtabIndex = 0;

        while (sectionHeaders[symtabIndex].sh_type != SHT_SYMTAB) {
            symtabIndex++;
        }

        auto strtabIter = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [this](Elf64_Shdr &sec) {
            return getSectionName(sec) == ".strtab";
        });

        auto strtabIndex = std::distance(sectionHeaders.begin(), strtabIter);

        for (auto &sec: sectionHeaders) {
            if (sec.sh_type == SHT_RELA) {
                sec.sh_link = symtabIndex;

            } else if (sec.sh_type == SHT_SYMTAB) {
                sec.sh_link = strtabIndex;
            }
        }

        // fix symbols

        for (int i = 0; i < symbols.size(); i++) {
            if (!symbolSecNames.contains(i)) {
                continue;
            }

            const auto name = symbolSecNames.at(i);

            if (isUselessSectionName(name)) {
                memset(&symbols[i], 0, sizeof(symbols[i]));
                continue;
            }

            auto iter = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [this, name](Elf64_Shdr &sec) {
                return getSectionName(sec) == name;
            });

            symbols[i].st_shndx = std::distance(sectionHeaders.begin(), iter);
        }
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

        for (auto &sec: sectionHeaders) {
            if (sec.sh_type == SHT_NULL) {
                continue;
            }

            auto name = getSectionName(sec);
            auto it = std::search(res.begin(), res.end(), name.begin(), name.end());
            sec.sh_name = std::distance(res.begin(), it);
        }

        return res;
    }

    void fixElfHeader() {
        elfHeader.e_machine = EM_AARCH64;
        elfHeader.e_shoff = elfHeader.e_ehsize;

        auto shstrtabIter = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [this](Elf64_Shdr &sec) {
            return getSectionName(sec) == ".shstrtab";
        });

        elfHeader.e_shstrndx = std::distance(sectionHeaders.begin(), shstrtabIter);
    }

    // section utils

    size_t getFuncSymbolIndex(Elf64_Shdr &section, size_t offset) {
        auto sectionIter = std::find_if(sectionHeaders.begin(), sectionHeaders.end(), [section](Elf64_Shdr &sec) {
            return sec.sh_name == section.sh_name; // why the FUCK can i not do `sec == section`?????
        });

        auto sectionIndex = std::distance(sectionHeaders.begin(), sectionIter);

        auto symbolIter = std::find_if(symbols.begin(), symbols.end(), [sectionIndex, offset](Elf64_Sym &sym) {
            return sym.st_shndx == sectionIndex
                   && sym.st_value == offset
                   && ELF64_ST_TYPE(sym.st_info) == STT_FUNC;
        });

        return std::distance(symbols.begin(), symbolIter);
    }

    Elf64_Shdr getRelocSecHdr(Elf64_Shdr &section) {
        auto relocSectionName = ".rela" + getSectionName(section);
        auto relocSecHdr = std::find_if(sectionHeaders.begin(), sectionHeaders.end(),
                                        [relocSectionName, this](Elf64_Shdr &s) {
                                            return getSectionName(s) == relocSectionName;
                                        });

        if (relocSecHdr == sectionHeaders.end()) {
            return {};
        }

        return *relocSecHdr;
    }

    std::vector<Elf64_Rela> getRelocs(Elf64_Shdr &relocSection) {
        std::vector<Elf64_Rela> relocs;

        auto base = relocSection.sh_offset;
        auto offset = 0;

        while (offset < relocSection.sh_size) {
            Elf64_Rela reloc;
            std::copy_n(file.begin() + base + offset, sizeof(Elf64_Rela), (uint8_t *) &reloc);
            relocs.push_back(reloc);
            offset += sizeof(Elf64_Rela);
        }

        return relocs;
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

    // utils

    Assembly disassemble(csh &handle, size_t offset, size_t size) {
        if (size == 0) {
            return {nullptr, 0};
        }

        cs_insn *insn;
        size_t count = cs_disasm(handle, &file[offset], size, 0, 0, &insn);

        if (count <= 0) {
            cs_close(&handle);
            throw std::runtime_error("decompilation failed");
        }

        return {insn, count};
    }

    static std::vector<char> compileArmCode(std::vector<std::vector<std::string>> &armCode, KeystoneWrapper &keystone) {
        std::vector<char> armAssembly;

        for (auto &codeGroup: armCode) {
            for (auto &line: codeGroup) {
                unsigned char *encode;
                size_t count, size;
                int retcode = ks_asm(keystone.handle, line.c_str(), 0, &encode, &size, &count);

                if (retcode) {
                    throw std::runtime_error("ks_asm FAILED on instruction " + line + " with code " +
                                             std::to_string(ks_errno(keystone.handle)));
                }

                armAssembly.insert(armAssembly.end(), encode, encode + size);
                ks_free(encode);
            }
        }

        return armAssembly;
    }

    static size_t alignOffset(size_t offset, unsigned long alignment) {
        if (alignment) {
            auto rem = offset % alignment;

            if (rem != 0) {
                return offset + alignment - rem;
            }
        }

        return offset;
    }
};

std::ifstream readFile(const char *path) {
    std::ifstream handle(path, std::ifstream::binary);

    if (handle.fail()) {
        throw std::runtime_error("Could not open file");
    }

    return handle;
}

void convert(const char *src, const char *dest) {
    std::basic_ifstream<char> fileHandle = readFile(src);
    auto file = std::vector<uint8_t>(std::istreambuf_iterator<char>(fileHandle),
                                     std::istreambuf_iterator<char>());
    fileHandle.close();

    ElfConverter converter(file);
    converter.convert(dest);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        throw std::runtime_error("Invalid argument count");
    }

    convert(argv[1], argv[2]);

    return 0;
}
