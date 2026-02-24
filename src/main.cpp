#include "xex2.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <memory>
#include <json.hpp>

namespace xexemu {

using nlohmann::json;

json output_json(const Xex2& xex, const Xex2Validator::VerificationResult* verification_result = nullptr) {
    json j;

    j["header"]["magic"] = "0x" + (std::stringstream() << std::hex << xex.header.magic).str();
    j["header"]["header_size"] = xex.header.header_size;
    j["header"]["security_offset"] = "0x" + (std::stringstream() << std::hex << xex.header.security_offset).str();
    j["header"]["header_count"] = xex.header.header_count;

    j["image"]["encrypted"] = xex.is_encrypted;
    j["image"]["compressed"] = xex.is_compressed;
    j["image"]["size"] = xex.image_data.size();

    j["opt_headers"] = json::array();
    for (const auto& opt_header : xex.opt_headers) {
        json h;
        h["id"] = "0x" + (std::stringstream() << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)opt_header.id).str();
        h["size"] = opt_header.size;
        j["opt_headers"].push_back(h);
    }

    if (xex.execution_info.title_id != 0) {
        j["execution_info"]["media_id"] = "0x" + (std::stringstream() << std::hex << xex.execution_info.media_id).str();
        j["execution_info"]["version"] = xex.execution_info.version;
        j["execution_info"]["base_version"] = xex.execution_info.base_version;
        j["execution_info"]["title_id"] = "0x" + (std::stringstream() << std::hex << xex.execution_info.title_id).str();
        j["execution_info"]["platform"] = (int)xex.execution_info.platform;
        j["execution_info"]["executable_type"] = (int)xex.execution_info.executable_type;
        j["execution_info"]["disc_number"] = (int)xex.execution_info.disc_number;
        j["execution_info"]["disc_count"] = (int)xex.execution_info.disc_count;
        j["execution_info"]["save_game_id"] = "0x" + (std::stringstream() << std::hex << xex.execution_info.save_game_id).str();
    }

    if (xex.file_format_info.image_size != 0) {
        j["file_format_info"]["encryption_type"] = "0x" + (std::stringstream() << std::hex << xex.file_format_info.encryption_type).str();
        j["file_format_info"]["compression_type"] = "0x" + (std::stringstream() << std::hex << xex.file_format_info.compression_type).str();
        j["file_format_info"]["encryption_flags"] = "0x" + (std::stringstream() << std::hex << xex.file_format_info.encryption_flags).str();
        j["file_format_info"]["block_count"] = xex.file_format_info.block_count;
        j["file_format_info"]["image_size"] = "0x" + (std::stringstream() << std::hex << xex.file_format_info.image_size).str();
        j["file_format_info"]["image_base"] = "0x" + (std::stringstream() << std::hex << xex.file_format_info.image_base).str();
    }

    j["certificate"]["title_id"] = "0x" + (std::stringstream() << std::hex << xex.certificate.title_id).str();
    j["certificate"]["platform"] = "0x" + (std::stringstream() << std::hex << xex.certificate.platform).str();
    j["certificate"]["executable_type"] = (int)xex.certificate.executable_type;
    j["certificate"]["page_size"] = (int)xex.certificate.page_size;
    j["certificate"]["minimum_version"] = xex.certificate.minimum_version;
    j["certificate"]["maximum_version"] = xex.certificate.maximum_version;
    j["certificate"]["allowed_media"] = "0x" + (std::stringstream() << std::hex << xex.certificate.allowed_media).str();
    j["certificate"]["certificate_type"] = (int)xex.certificate.certificate_type;
    j["certificate"]["title_flags"] = "0x" + (std::stringstream() << std::hex << (int)xex.certificate.title_flags).str();

    std::stringstream lan_key_ss;
    lan_key_ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < xex.certificate.lan_key.size(); i++) {
        lan_key_ss << std::setw(2) << (int)xex.certificate.lan_key[i];
    }
    j["certificate"]["lan_key"] = lan_key_ss.str();

    j["security_headers"] = json::array();
    for (const auto& sec_header : xex.security_headers) {
        json h;
        h["id"] = "0x" + (std::stringstream() << std::hex << std::setw(8) << std::setfill('0') << sec_header.id).str();
        h["size"] = sec_header.size;
        j["security_headers"].push_back(h);
    }

    j["resources"] = json::array();
    for (const auto& resource : xex.resource_infos) {
        json r;
        r["offset"] = "0x" + (std::stringstream() << std::hex << resource.offset).str();
        r["size"] = resource.size;
        r["flags"] = "0x" + (std::stringstream() << std::hex << resource.flags).str();
        r["title_id"] = "0x" + (std::stringstream() << std::hex << resource.title_id).str();
        j["resources"].push_back(r);
    }

    if (verification_result) {
        j["verification"]["hypervisor_signature"] = verification_result->hypervisor_valid ? "valid" : "invalid";
        j["verification"]["kernel_load_checks"] = verification_result->kernel_valid ? "pass" : "fail";
        j["verification"]["certificate_chain"] = verification_result->certificate_valid ? "valid" : "invalid";
        j["verification"]["media_restrictions"] = verification_result->media_valid ? "pass" : "fail";
        if (!verification_result->error_message.empty()) {
            j["verification"]["error"] = verification_result->error_message;
        }
    }

    return j;
}

std::string output_xml(const Xex2& xex, const Xex2Validator::VerificationResult* verification_result = nullptr) {
    std::stringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ss << "<xex>\n";

    ss << "  <header>\n";
    ss << "    <magic>0x" << std::hex << xex.header.magic << "</magic>\n";
    ss << "    <header_size>" << std::dec << xex.header.header_size << "</header_size>\n";
    ss << "    <security_offset>0x" << std::hex << xex.header.security_offset << "</security_offset>\n";
    ss << "    <header_count>" << std::dec << xex.header.header_count << "</header_count>\n";
    ss << "  </header>\n";

    ss << "  <image>\n";
    ss << "    <encrypted>" << (xex.is_encrypted ? "true" : "false") << "</encrypted>\n";
    ss << "    <compressed>" << (xex.is_compressed ? "true" : "false") << "</compressed>\n";
    ss << "    <size>" << std::dec << xex.image_data.size() << "</size>\n";
    ss << "  </image>\n";

    ss << "  <opt_headers>\n";
    for (const auto& opt_header : xex.opt_headers) {
        ss << "    <header>\n";
        ss << "      <id>0x" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)opt_header.id << "</id>\n";
        ss << "      <size>" << std::dec << opt_header.size << "</size>\n";
        ss << "    </header>\n";
    }
    ss << "  </opt_headers>\n";

    if (xex.execution_info.title_id != 0) {
        ss << "  <execution_info>\n";
        ss << "    <media_id>0x" << std::hex << xex.execution_info.media_id << "</media_id>\n";
        ss << "    <version>" << std::dec << xex.execution_info.version << "</version>\n";
        ss << "    <base_version>" << xex.execution_info.base_version << "</base_version>\n";
        ss << "    <title_id>0x" << std::hex << xex.execution_info.title_id << "</title_id>\n";
        ss << "    <platform>" << (int)xex.execution_info.platform << "</platform>\n";
        ss << "    <executable_type>" << (int)xex.execution_info.executable_type << "</executable_type>\n";
        ss << "    <disc_number>" << (int)xex.execution_info.disc_number << "</disc_number>\n";
        ss << "    <disc_count>" << (int)xex.execution_info.disc_count << "</disc_count>\n";
        ss << "    <save_game_id>0x" << std::hex << xex.execution_info.save_game_id << "</save_game_id>\n";
        ss << "  </execution_info>\n";
    }

    ss << "  <certificate>\n";
    ss << "    <title_id>0x" << std::hex << xex.certificate.title_id << "</title_id>\n";
    ss << "    <platform>0x" << std::hex << xex.certificate.platform << "</platform>\n";
    ss << "    <executable_type>" << (int)xex.certificate.executable_type << "</executable_type>\n";
    ss << "    <page_size>" << (int)xex.certificate.page_size << "</page_size>\n";
    ss << "    <minimum_version>" << std::dec << xex.certificate.minimum_version << "</minimum_version>\n";
    ss << "    <maximum_version>" << xex.certificate.maximum_version << "</maximum_version>\n";
    ss << "    <allowed_media>0x" << std::hex << xex.certificate.allowed_media << "</allowed_media>\n";
    ss << "    <certificate_type>" << (int)xex.certificate.certificate_type << "</certificate_type>\n";
    ss << "    <title_flags>0x" << std::hex << (int)xex.certificate.title_flags << "</title_flags>\n";

    ss << "    <lan_key>";
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < xex.certificate.lan_key.size(); i++) {
        ss << std::setw(2) << (int)xex.certificate.lan_key[i];
    }
    ss << "</lan_key>\n";
    ss << "  </certificate>\n";

    ss << "  <security_headers>\n";
    for (const auto& sec_header : xex.security_headers) {
        ss << "    <header>\n";
        ss << "      <id>0x" << std::hex << std::setw(8) << std::setfill('0') << sec_header.id << "</id>\n";
        ss << "      <size>" << std::dec << sec_header.size << "</size>\n";
        ss << "    </header>\n";
    }
    ss << "  </security_headers>\n";

    ss << "  <resources>\n";
    for (const auto& resource : xex.resource_infos) {
        ss << "    <resource>\n";
        ss << "      <offset>0x" << std::hex << resource.offset << "</offset>\n";
        ss << "      <size>" << std::dec << resource.size << "</size>\n";
        ss << "      <flags>0x" << std::hex << resource.flags << "</flags>\n";
        ss << "      <title_id>0x" << std::hex << resource.title_id << "</title_id>\n";
        ss << "    </resource>\n";
    }
    ss << "  </resources>\n";

    if (verification_result) {
        ss << "  <verification>\n";
        ss << "    <hypervisor_signature>" << (verification_result->hypervisor_valid ? "valid" : "invalid") << "</hypervisor_signature>\n";
        ss << "    <kernel_load_checks>" << (verification_result->kernel_valid ? "pass" : "fail") << "</kernel_load_checks>\n";
        ss << "    <certificate_chain>" << (verification_result->certificate_valid ? "valid" : "invalid") << "</certificate_chain>\n";
        ss << "    <media_restrictions>" << (verification_result->media_valid ? "pass" : "fail") << "</media_restrictions>\n";
        if (!verification_result->error_message.empty()) {
            ss << "    <error>" << verification_result->error_message << "</error>\n";
        }
        ss << "  </verification>\n";
    }

    ss << "</xex>\n";

    return ss.str();
}

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

std::string get_media_type_name(uint32_t media_type) {
    switch (media_type) {
        case 0x01: return "hard drive";
        case 0x02: return "dvd x2";
        case 0x04: return "cd";
        case 0x08: return "dvd x9";
        case 0x10: return "xbox 360 hard disk";
        case 0x20: return "nand";
        case 0x40: return "flash";
        case 0x80: return "usb";
        default: return "unknown";
    }
}

void print_allowed_media_types(uint32_t allowed_media) {
    std::cout << "allowed media types:" << std::endl;
    std::cout << "  raw value: 0x" << std::hex << allowed_media << std::dec << std::endl;
    std::cout << "  media types:" << std::endl;

    bool any_found = false;
    for (uint32_t bit = 0; bit < 32; bit++) {
        if (allowed_media & (1 << bit)) {
            std::string media_name = get_media_type_name(1 << bit);
            if (media_name != "unknown") {
                std::cout << "    - " << media_name << " (0x" << std::hex << (1 << bit) << std::dec << ")" << std::endl;
                any_found = true;
            }
        }
    }

    if (!any_found) {
        std::cout << "    none specified" << std::endl;
    }
    std::cout << std::endl;
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

    if (xex.allowed_media_types_opt_header != 0) {
        print_allowed_media_types(xex.allowed_media_types_opt_header);
    }

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

void print_exception_directory_status() {
    std::cout << "exception directory analysis" << std::endl;
    std::cout << "  parsed PE exception directory for unwind info extraction" << std::endl;
    std::cout << "  runtime function entries enumerated" << std::endl;
    std::cout << "  unwind info headers decoded" << std::endl;
    std::cout << std::endl;
}

}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <xex_file> [--verify] [--load] [--output-format json|xml|text] [--output-file <path>]" << std::endl;
        std::cerr << "       [--dump-header <path>] [--dump-certificate <path>] [--dump-opt-header <id> <path>]" << std::endl;
        std::cerr << "       [--set-title-id <value>] [--set-media-id <value>] [--set-min-version <value>]" << std::endl;
        std::cerr << "       [--set-max-version <value>] [--set-allowed-media <value>] [--write-xex <path>]" << std::endl;
        return 1;
    }

    std::string filepath = argv[1];
    bool verify = false;
    bool load = false;
    std::string output_format = "text";
    std::string output_file = "";
    std::string dump_header = "";
    std::string dump_certificate = "";
    std::string dump_opt_header_id = "";
    std::string dump_opt_header_path = "";
    uint32_t set_title_id = 0;
    bool has_set_title_id = false;
    uint32_t set_media_id = 0;
    bool has_set_media_id = false;
    uint32_t set_min_version = 0;
    bool has_set_min_version = false;
    uint32_t set_max_version = 0;
    bool has_set_max_version = false;
    uint32_t set_allowed_media = 0;
    bool has_set_allowed_media = false;
    std::string write_xex = "";

    for (int i = 2; i < argc; i++) {
        auto arg = std::string(argv[i]);
        if (arg == "--verify") {
            verify = true;
        } else if (arg == "--load") {
            load = true;
        } else if (arg == "--output-format") {
            if (i + 1 < argc) {
                output_format = argv[++i];
                if (output_format != "json" && output_format != "xml" && output_format != "text") {
                    std::cerr << "error: invalid output format, must be json, xml, or text" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "error: --output-format requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--output-file") {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                std::cerr << "error: --output-file requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--dump-header") {
            if (i + 1 < argc) {
                dump_header = argv[++i];
            } else {
                std::cerr << "error: --dump-header requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--dump-certificate") {
            if (i + 1 < argc) {
                dump_certificate = argv[++i];
            } else {
                std::cerr << "error: --dump-certificate requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--dump-opt-header") {
            if (i + 2 < argc) {
                dump_opt_header_id = argv[++i];
                dump_opt_header_path = argv[++i];
            } else {
                std::cerr << "error: --dump-opt-header requires two arguments (id and path)" << std::endl;
                return 1;
            }
        } else if (arg == "--set-title-id") {
            if (i + 1 < argc) {
                set_title_id = std::stoul(argv[++i], nullptr, 0);
                has_set_title_id = true;
            } else {
                std::cerr << "error: --set-title-id requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--set-media-id") {
            if (i + 1 < argc) {
                set_media_id = std::stoul(argv[++i], nullptr, 0);
                has_set_media_id = true;
            } else {
                std::cerr << "error: --set-media-id requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--set-min-version") {
            if (i + 1 < argc) {
                set_min_version = std::stoul(argv[++i], nullptr, 0);
                has_set_min_version = true;
            } else {
                std::cerr << "error: --set-min-version requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--set-max-version") {
            if (i + 1 < argc) {
                set_max_version = std::stoul(argv[++i], nullptr, 0);
                has_set_max_version = true;
            } else {
                std::cerr << "error: --set-max-version requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--set-allowed-media") {
            if (i + 1 < argc) {
                set_allowed_media = std::stoul(argv[++i], nullptr, 0);
                has_set_allowed_media = true;
            } else {
                std::cerr << "error: --set-allowed-media requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--write-xex") {
            if (i + 1 < argc) {
                write_xex = argv[++i];
            } else {
                std::cerr << "error: --write-xex requires an argument" << std::endl;
                return 1;
            }
        }
    }

    try {
        xexemu::Xex2 xex = xexemu::parse_xex2(filepath);

        xexemu::Xex2Modifier modifier(xex);

        if (has_set_title_id) {
            modifier.set_title_id(set_title_id);
        }
        if (has_set_media_id) {
            modifier.set_media_id(set_media_id);
        }
        if (has_set_min_version) {
            modifier.set_minimum_version(set_min_version);
        }
        if (has_set_max_version) {
            modifier.set_maximum_version(set_max_version);
        }
        if (has_set_allowed_media) {
            modifier.set_allowed_media(set_allowed_media);
        }

        if (!dump_header.empty()) {
            if (modifier.dump_header(dump_header)) {
                std::cout << "dumped header to " << dump_header << std::endl;
            } else {
                std::cerr << "error: failed to dump header" << std::endl;
            }
        }

        if (!dump_certificate.empty()) {
            if (modifier.dump_certificate(dump_certificate)) {
                std::cout << "dumped certificate to " << dump_certificate << std::endl;
            } else {
                std::cerr << "error: failed to dump certificate" << std::endl;
            }
        }

        if (!dump_opt_header_path.empty()) {
            uint32_t opt_header_id = std::stoul(dump_opt_header_id, nullptr, 0);
            if (modifier.dump_opt_header(static_cast<xexemu::XexOptHeaderId>(opt_header_id), dump_opt_header_path)) {
                std::cout << "dumped optional header 0x" << std::hex << opt_header_id << std::dec << " to " << dump_opt_header_path << std::endl;
            } else {
                std::cerr << "error: failed to dump optional header" << std::endl;
            }
        }

        if (!write_xex.empty()) {
            if (modifier.write_xex(write_xex)) {
                std::cout << "wrote modified xex to " << write_xex << std::endl;
            } else {
                std::cerr << "error: failed to write xex" << std::endl;
            }
        }

        xexemu::Xex2Validator::VerificationResult* verification_result = nullptr;
        xexemu::Xex2Validator::VerificationResult result_value;

        if (verify) {
            xexemu::Xex2Validator validator(xex);
            result_value = validator.full_verification();
            verification_result = &result_value;
        }

        if (output_format == "json") {
            nlohmann::json j = output_json(xex, verification_result);
            std::string output = j.dump(2);

            if (!output_file.empty()) {
                std::ofstream out(output_file);
                out << output;
                out.close();
            } else {
                std::cout << output << std::endl;
            }
        } else if (output_format == "xml") {
            std::string output = output_xml(xex, verification_result);

            if (!output_file.empty()) {
                std::ofstream out(output_file);
                out << output;
                out.close();
            } else {
                std::cout << output << std::endl;
            }
        } else {
            xexemu::print_analysis(xex);

            if (verification_result) {
                xexemu::print_verification_result(*verification_result);
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

                    if (loader.parse_exception_directory()) {
                        xexemu::print_exception_directory_status();
                    } else {
                        std::cout << "exception directory parsing: fail" << std::endl;
                    }
                } else {
                    std::cout << "image loading: fail" << std::endl;
                }
                std::cout << std::endl;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
