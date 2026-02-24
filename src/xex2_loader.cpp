#include "xex2.h"
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace xexemu {

namespace {
constexpr uint32_t DOS_MAGIC = 0x5A4D;
constexpr uint32_t PE_MAGIC_32 = 0x010B;
constexpr uint32_t PE_MAGIC_64 = 0x020B;
constexpr uint32_t SECTION_READABLE = 0x40000000;
constexpr uint32_t SECTION_WRITABLE = 0x80000000;
constexpr uint32_t SECTION_EXECUTABLE = 0x20000000;

template<typename T>
T read_struct(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + sizeof(T) > data.size()) {
        throw std::runtime_error("buffer overflow reading struct");
    }
    T result;
    std::memcpy(&result, data.data() + offset, sizeof(T));
    return result;
}
}

struct PeHeaderDOS {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct PeHeaderNT {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    uint64_t data_directory[16];
};

struct PeSectionHeader {
    uint8_t  name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

struct ImageImportDescriptor {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
};

struct ImageTlsDirectory {
    uint32_t start_address_of_raw_data;
    uint32_t end_address_of_raw_data;
    uint32_t address_of_index;
    uint32_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
};

struct RuntimeFunction {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_info_address;
};

struct UnwindInfoHeader {
    uint8_t version_flags;
    uint8_t size_of_prolog;
    uint8_t count_of_codes;
    uint8_t frame_register_offset;
};

Xex2Loader::Xex2Loader(const Xex2& xex) : xex_(xex), is_loaded_(false) {}

bool Xex2Loader::parse_exception_directory() {
    if (!is_loaded_) {
        return false;
    }

    const auto dos_header = read_struct<PeHeaderDOS>(decrypted_image_, 0);
    uint32_t nt_offset = dos_header.e_lfanew;
    const auto nt_header = read_struct<PeHeaderNT>(decrypted_image_, nt_offset);

    uint32_t exception_dir_rva = static_cast<uint32_t>(nt_header.data_directory[3] & 0xFFFFFFFF);
    uint32_t exception_dir_size = static_cast<uint32_t>((nt_header.data_directory[3] >> 32) & 0xFFFFFFFF);

    if (exception_dir_rva == 0 || exception_dir_size == 0) {
        return true;
    }

    if (exception_dir_rva + exception_dir_size > decrypted_image_.size()) {
        return false;
    }

    size_t function_count = exception_dir_size / sizeof(RuntimeFunction);
    for (size_t i = 0; i < function_count; i++) {
        RuntimeFunction func;
        size_t offset = exception_dir_rva + i * sizeof(RuntimeFunction);
        
        if (offset + sizeof(RuntimeFunction) > decrypted_image_.size()) {
            break;
        }

        std::memcpy(&func, decrypted_image_.data() + offset, sizeof(RuntimeFunction));

        if (func.begin_address == 0 && func.end_address == 0) {
            continue;
        }

        if (func.unwind_info_address < decrypted_image_.size()) {
            UnwindInfoHeader unwind_header;
            if (func.unwind_info_address + sizeof(UnwindInfoHeader) <= decrypted_image_.size()) {
                std::memcpy(&unwind_header, decrypted_image_.data() + func.unwind_info_address, sizeof(UnwindInfoHeader));
                
                uint8_t version = unwind_header.version_flags & 0x07;
                uint8_t flags = (unwind_header.version_flags >> 3) & 0x1F;
                bool has_exception_handler = (flags & 0x01) != 0;
                
                uint8_t frame_register = (unwind_header.frame_register_offset >> 4) & 0x0F;
                uint8_t frame_offset = unwind_header.frame_register_offset & 0x0F;
            }
        }
    }

    return true;
}

bool Xex2Loader::load() {
    decrypted_image_ = xex_.image_data;
    is_loaded_ = true;
    return true;
}

bool Xex2Loader::map_segments() {
    if (!is_loaded_) {
        return false;
    }

    if (decrypted_image_.size() < sizeof(PeHeaderDOS)) {
        return false;
    }

    const auto dos_header = read_struct<PeHeaderDOS>(decrypted_image_, 0);

    if (dos_header.e_magic != DOS_MAGIC) {
        return false;
    }

    if (dos_header.e_lfanew >= decrypted_image_.size()) {
        return false;
    }

    uint32_t nt_offset = dos_header.e_lfanew;
    if (nt_offset + sizeof(PeHeaderNT) > decrypted_image_.size()) {
        return false;
    }

    const auto nt_header = read_struct<PeHeaderNT>(decrypted_image_, nt_offset);

    if (nt_header.magic != PE_MAGIC_32 && nt_header.magic != PE_MAGIC_64) {
        return false;
    }

    const auto file_header = read_struct<PeFileHeader>(decrypted_image_, nt_offset + 4);

    uint32_t section_offset = nt_offset + 4 + sizeof(PeFileHeader);
    if (section_offset + file_header.number_of_sections * sizeof(PeSectionHeader) > decrypted_image_.size()) {
        return false;
    }

    std::vector<PeSectionHeader> sections(file_header.number_of_sections);
    std::memcpy(sections.data(), decrypted_image_.data() + section_offset, sections.size() * sizeof(PeSectionHeader));

    for (const auto& section : sections) {
    }

    return true;
}

bool Xex2Loader::resolve_imports() {
    if (!is_loaded_) {
        return false;
    }

    const auto dos_header = read_struct<PeHeaderDOS>(decrypted_image_, 0);

    uint32_t nt_offset = dos_header.e_lfanew;
    const auto nt_header = read_struct<PeHeaderNT>(decrypted_image_, nt_offset);

    uint32_t import_dir_rva = static_cast<uint32_t>(nt_header.data_directory[1] & 0xFFFFFFFF);
    uint32_t import_dir_size = static_cast<uint32_t>((nt_header.data_directory[1] >> 32) & 0xFFFFFFFF);

    if (import_dir_rva == 0 || import_dir_size == 0) {
        return true;
    }

    if (import_dir_rva + import_dir_size > decrypted_image_.size()) {
        return false;
    }

    size_t desc_count = import_dir_size / sizeof(ImageImportDescriptor);
    for (size_t i = 0; i < desc_count; i++) {
        ImageImportDescriptor desc;
        std::memcpy(&desc, decrypted_image_.data() + import_dir_rva + i * sizeof(ImageImportDescriptor), sizeof(ImageImportDescriptor));

        if (desc.name == 0) {
            break;
        }

        if (desc.name < decrypted_image_.size()) {
            size_t j = 0;
            while (desc.name + j < decrypted_image_.size() && decrypted_image_[desc.name + j] != 0) {
                j++;
            }
        }

        uint32_t thunk_addr = desc.first_thunk ? desc.first_thunk : desc.original_first_thunk;
        while (true) {
            if (thunk_addr + 4 > decrypted_image_.size()) {
                break;
            }

            uint64_t thunk_val;
            std::memcpy(&thunk_val, decrypted_image_.data() + thunk_addr, 8);

            if (thunk_val == 0) {
                break;
            }

            bool is_ordinal = (thunk_val & (1ULL << 63)) != 0;
            if (!is_ordinal) {
                uint32_t hint_name_rva = static_cast<uint32_t>(thunk_val & 0xFFFFFFFF);
                if (hint_name_rva + 2 < decrypted_image_.size()) {
                    size_t k = 0;
                    while (hint_name_rva + 2 + k < decrypted_image_.size() && decrypted_image_[hint_name_rva + 2 + k] != 0) {
                        k++;
                    }
                }
            }

            thunk_addr += 8;
        }
    }

    return true;
}

bool Xex2Loader::initialise_tls() {
    if (!is_loaded_) {
        return false;
    }

    const auto dos_header = read_struct<PeHeaderDOS>(decrypted_image_, 0);

    uint32_t nt_offset = dos_header.e_lfanew;
    const auto nt_header = read_struct<PeHeaderNT>(decrypted_image_, nt_offset);

    uint32_t tls_dir_rva = static_cast<uint32_t>(nt_header.data_directory[9] & 0xFFFFFFFF);
    uint32_t tls_dir_size = static_cast<uint32_t>((nt_header.data_directory[9] >> 32) & 0xFFFFFFFF);

    if (tls_dir_rva == 0 || tls_dir_size == 0) {
        return true;
    }

    if (tls_dir_rva + sizeof(ImageTlsDirectory) > decrypted_image_.size()) {
        return false;
    }

    ImageTlsDirectory tls_dir;
    std::memcpy(&tls_dir, decrypted_image_.data() + tls_dir_rva, sizeof(ImageTlsDirectory));

    uint32_t tls_data_size = tls_dir.end_address_of_raw_data - tls_dir.start_address_of_raw_data;
    if (tls_dir.start_address_of_raw_data + tls_data_size <= decrypted_image_.size()) {
    }



    if (tls_dir.address_of_callbacks != 0) {
        uint32_t callback_addr = tls_dir.address_of_callbacks;
        while (true) {
            if (callback_addr + 8 > decrypted_image_.size()) {
                break;
            }

            uint64_t callback;
            std::memcpy(&callback, decrypted_image_.data() + callback_addr, 8);

            if (callback == 0) {
                break;
            }

            callback_addr += 8;
        }
    }

    return true;
}

}
