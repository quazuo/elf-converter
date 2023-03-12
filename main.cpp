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
                std::vector<Elf64_Rela> relocs = getRelocs(sec);
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
                        auto codeWithReloc = convertOpWithReloc(currInstr);
                        currCode = codeWithReloc.first;
                        auto currRelocType = codeWithReloc.second;
                        Elf64_Rela *currReloc = &relocs[relocIndexes.at(i)];

                        currReloc->r_info = ELF64_R_INFO(ELF64_R_SYM(currReloc->r_info), currRelocType);
                        currReloc->r_offset = currInstrOffset;

                        if (currRelocType == R_AARCH64_CALL26) {
                            currReloc->r_addend = 0;
                        }

                        if (currRelocType == R_AARCH64_NONE)
                            throw std::runtime_error("XD");

                    } else {
                        currCode = convertOp(currInstr, i, jumps);
                    }

                    armCode.push_back(currCode);

                    for (auto &str: currCode) {
                        std::cout << currInstrOffset << "\t" << str << "\n";
                    }
                    std::cout << "\n";

                    currInstrOffset += 4 * currCode.size();
                    currFuncSize += 4 * currCode.size();
                }

                std::string mergedCode;
                for (auto &codeGroup: armCode) {
                    for (auto &line: codeGroup) {
                        mergedCode.append(line).append("\n");
                    }
                }

                unsigned char *encode;
                size_t count;
                int retcode = ks_asm(keystone.handle, mergedCode.c_str(), currOffset, &encode, &currSize, &count);

                if (retcode) {
                    throw std::runtime_error("ks_asm FAILED on instruction " + mergedCode + " with code " + std::to_string(ks_errno(keystone.handle)));
                }

                newFile.insert(newFile.end(), encode, encode + currSize);
                newRelocTables.emplace(alignOffset(sectionsOffset + currOffset + currSize, relocsHeader.sh_addralign), relocs);

                ks_free(encode);

            } else if (sec.sh_type == SHT_RELA && !(sectionHeaders[sec.sh_info].sh_flags & SHF_EXECINSTR)) {
                std::vector<Elf64_Rela> relocs = getRelocs(sec);

                for (auto &reloc : relocs) {
                    reloc.r_info = ELF64_R_INFO(ELF64_R_SYM(reloc.r_info), R_AARCH64_ABS64);
                }

                newRelocTables.emplace(currOffset, relocs);

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
        for (auto &[pos, relocTable] : newRelocTables) {
            size_t offset = 0;

            for (auto &reloc : relocTable) {
                std::copy_n((uint8_t *)&reloc, sizeof reloc, newFile.begin() + pos + offset);
                offset += sizeof reloc;
            }
        }

        // symtab section!
        size_t offset = 0;

        for (auto &sym : symbols) {
            std::copy_n((uint8_t *)&sym, sizeof sym, newFile.begin() + symtabOffset + offset);
            offset += sizeof sym;
        }

        // section headers!
        offset = 0;

        for (auto &header : sectionHeaders) {
            std::copy_n((uint8_t *)&header, sizeof header, newFile.begin() + elfHeader.e_ehsize + offset);
            offset += sizeof header;
        }

        // It is finished.

        // debug
//        for (int i = 0; i < newFile.size(); i += 2) {
//
//            if (i % 16 == 0)
//                std::cout << "\n" << std::setfill('0') << std::setw(7) << std::hex << i << " ";
//
//            std::cout
//                << std::setfill('0') << std::setw(2) << std::hex
//                << (int) *((uint8_t *) &newFile[i + 1])
//                << std::setfill('0') << std::setw(2) << std::hex
//                << (int) *((uint8_t *) &newFile[i])
//                << " ";
//        }
//
//        std::cout << "\n";




        // emit file
        std::ofstream handle(path, std::ios::binary);

        if (handle.fail()) {
            throw std::runtime_error("Could not open file");
        }

        for (auto c : newFile) {
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
        return *relocSecHdr;
    }

    std::vector<Elf64_Rela> getRelocs(Elf64_Shdr &section) {
        std::vector<Elf64_Rela> relocs;
        auto relocSecHdr = getRelocSecHdr(section);

        auto base = relocSecHdr.sh_offset;
        auto offset = 0;

        while (offset < relocSecHdr.sh_size) {
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
            return { nullptr, 0 };
        }

        cs_insn *insn;
        size_t count = cs_disasm(handle, &file[offset], size, 0, 0, &insn);

        if (count <= 0) {
            cs_close(&handle);
            throw std::runtime_error("decompilation failed");
        }

        // todo - debug
//        size_t j;
//        for (j = 0; j < count; j++) {
//            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
//                   insn[j].op_str);
//        }

        return {insn, count};
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
