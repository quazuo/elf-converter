#ifndef CONVERTER_STRUCT_H
#define CONVERTER_STRUCT_H

#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include <stdexcept>

struct Jump {
    int from;
    int offset;
};

struct Assembly {
    cs_insn *insn;
    size_t count;

    ~Assembly() {
        cs_free(insn, count);
    }
};

struct CapstoneWrapper {
    csh handle{};

    CapstoneWrapper() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            throw std::runtime_error("capstone engine initialization failed");
        }
    }

    ~CapstoneWrapper() {
        cs_close(&handle);
    }
};

struct KeystoneWrapper {
    ks_engine *handle{};

    KeystoneWrapper() {
        int code;
        if ((code = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &handle)) != KS_ERR_OK) {
            throw std::runtime_error("keystone engine initialization failed with code " + std::to_string(code));
        }
    }

    ~KeystoneWrapper() {
        ks_close(handle);
    }
};

#endif //CONVERTER_STRUCT_H
