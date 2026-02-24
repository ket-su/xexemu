#include "xex2.h"
#include <iostream>
#include <iomanip>
#include <fstream>

namespace xexemu {

void print_hex(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    auto count = std::min(data.size(), max_bytes);
    for (size_t i = 0; i < count; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i < count - 1 && (i + 1) % 4 == 0) {
            std::cout << " ";
        }
    }
    if (data.size() > max_bytes) {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;
}

void print_execution_info(const XexExecutionInfo& info) {
    std::cout << "execution info:" << std::endl;
    std::cout << "  media id: 0x" << std::hex << info.media_id << std::dec << std::endl;
    std::cout << "  version: " << info.version << std::endl;
    std::cout << "  base version: " << info.base_version << std::endl;
    std::cout << "  title id: 0x" << std::hex << info.title_id << std::dec << std::endl;
    std::cout << "  platform: " << (int)info.platform << std::endl;
    std::cout << "  executable type: " << (int)info.executable_type << std::endl;
    std::cout << "  disc number: " << (int)info.disc_number << "/" << (int)info.disc_count << std::endl;
    std::cout << "  save game id: 0x" << std::hex << info.save_game_id << std::dec << std::endl;
}

void print_file_format_info(const XexFileFormatInfo& info) {
    std::cout << "file format info:" << std::endl;
    std::cout << "  encryption type: 0x" << std::hex << info.encryption_type << std::dec << std::endl;
    std::cout << "  compression type: 0x" << std::hex << info.compression_type << std::dec << std::endl;
    std::cout << "  encryption flags: 0x" << std::hex << info.encryption_flags << std::dec << std::endl;
    std::cout << "  block count: " << info.block_count << std::endl;
    std::cout << "  image size: 0x" << std::hex << info.image_size << std::dec << std::endl;
    std::cout << "  image base: 0x" << std::hex << info.image_base << std::dec << std::endl;
}

void print_certificate(const XexCertificate& cert) {
    std::cout << "certificate:" << std::endl;
    std::cout << "  title id: 0x" << std::hex << cert.title_id << std::dec << std::endl;
    std::cout << "  platform: 0x" << std::hex << cert.platform << std::dec << std::endl;
    std::cout << "  executable type: " << (int)cert.executable_type << std::endl;
    std::cout << "  page size: " << (int)cert.page_size << std::endl;
    std::cout << "  minimum version: " << cert.minimum_version << std::endl;
    std::cout << "  maximum version: " << cert.maximum_version << std::endl;
    std::cout << "  allowed media: 0x" << std::hex << cert.allowed_media << std::dec << std::endl;
    std::cout << "  certificate type: " << (int)cert.certificate_type << std::endl;
    std::cout << "  title flags: 0x" << std::hex << (int)cert.title_flags << std::dec << std::endl;
    std::cout << "  lan key: ";
    print_hex(std::vector<uint8_t>(cert.lan_key.begin(), cert.lan_key.end()));
}

void print_analysis(const Xex2& xex) {
    std::cout << "xex2 analysis" << std::endl;
    std::cout << std::endl;

    std::cout << "header info:" << std::endl;
    std::cout << "  magic: 0x" << std::hex << xex.header.magic << std::dec << std::endl;
    std::cout << "  header size: " << xex.header.header_size << " bytes" << std::endl;
    std::cout << "  security offset: 0x" << std::hex << xex.header.security_offset << std::dec << std::endl;
    std::cout << "  header count: " << xex.header.header_count << std::endl;
    std::cout << std::endl;

    std::cout << "image status:" << std::endl;
    std::cout << "  encrypted: " << (xex.is_encrypted ? "yes" : "no") << std::endl;
    std::cout << "  compressed: " << (xex.is_compressed ? "yes" : "no") << std::endl;
    std::cout << "  image size: " << xex.image_data.size() << " bytes" << std::endl;
    std::cout << std::endl;

    std::cout << "optional headers: " << xex.opt_headers.size() << std::endl;
    for (const auto& opt_header : xex.opt_headers) {
        std::cout << "  id: 0x" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)opt_header.id << std::dec;
        std::cout << ", size: " << opt_header.size << " bytes" << std::endl;
    }
    std::cout << std::endl;

    if (xex.execution_info.title_id != 0) {
        print_execution_info(xex.execution_info);
        std::cout << std::endl;
    }

    if (xex.file_format_info.image_size != 0) {
        print_file_format_info(xex.file_format_info);
        std::cout << std::endl;
    }

    print_certificate(xex.certificate);
    std::cout << std::endl;

    std::cout << "security headers: " << xex.security_headers.size() << std::endl;
    for (const auto& sec_header : xex.security_headers) {
        std::cout << "  id: 0x" << std::hex << std::setw(8) << std::setfill('0') << sec_header.id << std::dec;
        std::cout << ", size: " << sec_header.size << " bytes" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "resource sections: " << xex.resource_infos.size() << std::endl;
    for (const auto& resource : xex.resource_infos) {
        std::cout << "  offset: 0x" << std::hex << resource.offset << std::dec;
        std::cout << ", size: " << resource.size << " bytes";
        std::cout << ", flags: 0x" << std::hex << resource.flags << std::dec;
        std::cout << ", title id: 0x" << std::hex << resource.title_id << std::dec << std::endl;
    }
    std::cout << std::endl;
}

void print_verification_result(const Xex2Validator::VerificationResult& result) {
    std::cout << "verification results" << std::endl;
    std::cout << std::endl;
    std::cout << "hypervisor signature: " << (result.hypervisor_valid ? "valid" : "invalid") << std::endl;
    std::cout << "kernel load checks: " << (result.kernel_valid ? "pass" : "fail") << std::endl;
    std::cout << "certificate chain: " << (result.certificate_valid ? "valid" : "invalid") << std::endl;
    std::cout << "media restrictions: " << (result.media_valid ? "pass" : "fail") << std::endl;

    if (!result.error_message.empty()) {
        std::cout << std::endl;
        std::cout << "error: " << result.error_message << std::endl;
    }
    std::cout << std::endl;
}

void print_loader_status(const Xex2Loader& loader) {
    std::cout << "loader emulation" << std::endl;
    std::cout << std::endl;
}

}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <xex_file> [--verify] [--load]" << std::endl;
        return 1;
    }

    std::string filepath = argv[1];
    bool verify = false;
    bool load = false;

    for (int i = 2; i < argc; i++) {
        auto arg = std::string(argv[i]);
        if (arg == "--verify") {
            verify = true;
        } else if (arg == "--load") {
            load = true;
        }
    }

    try {
        xexemu::Xex2 xex = xexemu::parse_xex2(filepath);
        xexemu::print_analysis(xex);

        if (verify) {
            xexemu::Xex2Validator validator(xex);
            auto result = validator.full_verification();
            xexemu::print_verification_result(result);
        }

        if (load) {
            xexemu::Xex2Loader loader(xex);
            if (loader.load()) {
                xexemu::print_loader_status(loader);

                if (loader.map_segments()) {
                    std::cout << "segment mapping: ok" << std::endl;
                } else {
                    std::cout << "segment mapping: fail" << std::endl;
                }

                if (loader.resolve_imports()) {
                    std::cout << "import resolution: ok" << std::endl;
                } else {
                    std::cout << "import resolution: fail" << std::endl;
                }

                if (loader.initialise_tls()) {
                    std::cout << "tls initialisation: ok" << std::endl;
                } else {
                    std::cout << "tls initialisation: fail" << std::endl;
                }
            } else {
                std::cout << "image loading: fail" << std::endl;
            }
            std::cout << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
