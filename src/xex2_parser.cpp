#include "xex2.h"
#include "xex2_exceptions.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <string>

namespace xexemu {

class Xex2Parser {
public:
    explicit Xex2Parser(std::string_view filepath) : filepath_(filepath) {}

    Xex2 parse() {
        std::string filepath_str(filepath_);
        std::ifstream file(filepath_str, std::ios::binary);
        if (!file) {
            throw FileOpenException(filepath_str, "file does not exist or cannot be opened");
        }

        file_.swap(file);

        Xex2 xex;
        xex.filepath_ = filepath_str;
        parse_header(xex);
        parse_optional_headers(xex);
        parse_security_info(xex);
        parse_image_data(xex);

        return xex;
    }

private:
    std::string filepath_;
    std::ifstream file_;

    void parse_header(Xex2& xex) {
        file_.seekg(0);
        file_.read(reinterpret_cast<char*>(&xex.header), sizeof(XexHeader));

        if (!file_ || file_.gcount() != static_cast<std::streamsize>(sizeof(XexHeader))) {
            throw InsufficientDataException("XexHeader", sizeof(XexHeader), file_.gcount());
        }

        if (xex.header.magic != XEX_MAGIC) {
            throw InvalidMagicException("0x58455832", "0x" + std::to_string(xex.header.magic));
        }

        xex.is_encrypted = false;
        xex.is_compressed = false;
    }

    void parse_optional_headers(Xex2& xex) {
        uint32_t offset = sizeof(XexHeader);
        xex.opt_headers.reserve(xex.header.header_count);

        for (uint32_t i = 0; i < xex.header.header_count; i++) {
            file_.seekg(offset);

            XexOptHeader opt_header;
            uint32_t id, size;
            file_.read(reinterpret_cast<char*>(&id), sizeof(uint32_t));
            file_.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));

            if (!file_ || file_.gcount() != static_cast<std::streamsize>(sizeof(uint32_t) * 2)) {
                throw InsufficientDataException("XexOptHeader id/size", sizeof(uint32_t) * 2, file_.gcount());
            }

            opt_header.id = static_cast<XexOptHeaderId>(id);
            opt_header.size = size;

            uint32_t data_offset = offset + 8;
            uint32_t next_offset = ((data_offset + size + 0xF) & ~0xF);

            opt_header.data.resize(size);
            file_.seekg(data_offset);
            file_.read(reinterpret_cast<char*>(opt_header.data.data()), size);

            if (!file_ || file_.gcount() != static_cast<std::streamsize>(size)) {
                throw FileReadException(std::string(filepath_), size, file_.gcount());
            }

            xex.opt_headers.push_back(opt_header);

            offset = next_offset;
        }

        process_optional_headers(xex);
    }

    void process_optional_headers(Xex2& xex) {
        for (const auto& opt_header : xex.opt_headers) {
            switch (opt_header.id) {
                case XexOptHeaderId::ExecutionInfo:
                    parse_execution_info(opt_header, xex);
                    break;
                case XexOptHeaderId::FileFormatInfo:
                    parse_file_format_info(opt_header, xex);
                    break;
                case XexOptHeaderId::ResourceInfo:
                    parse_resource_info(opt_header, xex);
                    break;
                default:
                    break;
            }
        }
    }

    void parse_execution_info(const XexOptHeader& opt_header, Xex2& xex) {
        if (opt_header.data.size() >= sizeof(XexExecutionInfo)) {
            std::memcpy(&xex.execution_info, opt_header.data.data(), sizeof(XexExecutionInfo));
        }
    }

    void parse_file_format_info(const XexOptHeader& opt_header, Xex2& xex) {
        if (opt_header.data.size() >= sizeof(XexFileFormatInfo)) {
            std::memcpy(&xex.file_format_info, opt_header.data.data(), sizeof(XexFileFormatInfo));
        }
    }

    void parse_resource_info(const XexOptHeader& opt_header, Xex2& xex) {
        size_t count = opt_header.data.size() / sizeof(XexResourceInfo);
        xex.resource_infos.reserve(count);
        for (size_t i = 0; i < count; i++) {
            XexResourceInfo info;
            std::memcpy(&info, opt_header.data.data() + i * sizeof(XexResourceInfo), sizeof(XexResourceInfo));
            xex.resource_infos.push_back(info);
        }
    }

    void parse_security_info(Xex2& xex) {
        file_.seekg(xex.header.security_offset);

        uint32_t cert_size;
        file_.read(reinterpret_cast<char*>(&cert_size), sizeof(uint32_t));

        xex.certificate.size = cert_size;

        uint32_t cert_data_size = cert_size - sizeof(uint32_t);
        std::vector<uint8_t> cert_data(cert_data_size);
        file_.read(reinterpret_cast<char*>(cert_data.data()), cert_data_size);

        parse_certificate(cert_data, xex);

        uint32_t header_count;
        file_.read(reinterpret_cast<char*>(&header_count), sizeof(uint32_t));

        uint32_t offset = xex.header.security_offset + 4 + cert_data_size + 4;
        xex.security_headers.reserve(header_count);
        for (uint32_t i = 0; i < header_count; i++) {
            file_.seekg(offset);

            XexSecurityHeader sec_header;
            uint32_t id, size;
            file_.read(reinterpret_cast<char*>(&id), sizeof(uint32_t));
            file_.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));

            sec_header.id = id;
            sec_header.size = size;
            sec_header.data.resize(size);
            file_.read(reinterpret_cast<char*>(sec_header.data.data()), size);

            xex.security_headers.push_back(sec_header);

            offset += 8 + ((size + 0xF) & ~0xF);
        }

        process_security_headers(xex);
    }

    void parse_certificate(const std::vector<uint8_t>& data, Xex2& xex) {
        size_t offset = 0;

        xex.certificate.time_date_1 = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.time_date_2 = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.title_id = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.platform = *reinterpret_cast<const uint16_t*>(data.data() + offset);
        offset += 2;
        xex.certificate.executable_type = data[offset];
        offset += 1;
        xex.certificate.page_size = data[offset];
        offset += 1;
        xex.certificate.minimum_version = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.maximum_version = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.allowed_media = *reinterpret_cast<const uint32_t*>(data.data() + offset);
        offset += 4;
        xex.certificate.certificate_type = data[offset];
        offset += 1;
        xex.certificate.title_flags = data[offset];
        offset += 1;
        std::memcpy(xex.certificate.lan_key.data(), data.data() + offset, 20);
        offset += 20;
        std::memcpy(xex.certificate.signature_key.data(), data.data() + offset, 20);
        offset += 20;
        std::memcpy(xex.certificate.signature.data(), data.data() + offset, 256);
        offset += 256;
    }

    void process_security_headers(Xex2& xex) {
        for (const auto& sec_header : xex.security_headers) {
            if (sec_header.id == 0x00010006) {
                xex.is_encrypted = true;
            } else if (sec_header.id == 0x00010005) {
                xex.is_compressed = true;
            }
        }
    }

    void parse_image_data(Xex2& xex) {
        uint32_t image_offset = ((xex.header.header_size + 0xFFF) & ~0xFFF);
        file_.seekg(0, std::ios::end);
        if (!file_) {
            throw FileOpenException(std::string(filepath_), "failed to seek to end of file");
        }

        uint32_t file_size = file_.tellg();
        if (file_size < image_offset) {
            throw CorruptHeaderException("XexHeader", "header_size exceeds file size");
        }

        uint32_t image_size = file_size - image_offset;

        xex.image_data.resize(image_size);
        file_.seekg(image_offset);
        file_.read(reinterpret_cast<char*>(xex.image_data.data()), image_size);

        if (!file_ || file_.gcount() != static_cast<std::streamsize>(image_size)) {
            throw FileReadException(std::string(filepath_), image_size, file_.gcount());
        }
    }
};

Xex2 parse_xex2(std::string_view filepath) {
    Xex2Parser parser(filepath);
    return parser.parse();
}

}
