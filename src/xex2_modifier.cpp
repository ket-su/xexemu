#include "xex2.h"
#include <fstream>
#include <cstring>
#include <iomanip>

namespace xexemu {

Xex2Modifier::Xex2Modifier(Xex2& xex) : xex_(xex) {}

bool Xex2Modifier::dump_header(const std::string& output_path) const {
    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(&xex_.header), sizeof(XexHeader));

    uint32_t offset = sizeof(XexHeader);
    for (const auto& opt_header : xex_.opt_headers) {
        out.seekp(offset);
        out.write(reinterpret_cast<const char*>(&opt_header.id), sizeof(uint32_t));
        out.write(reinterpret_cast<const char*>(&opt_header.size), sizeof(uint32_t));

        uint32_t data_offset = offset + 8;
        out.seekp(data_offset);
        out.write(reinterpret_cast<const char*>(opt_header.data.data()), opt_header.size);

        offset = ((data_offset + opt_header.size + 0xF) & ~0xF);
    }

    out.close();
    return true;
}

bool Xex2Modifier::dump_certificate(const std::string& output_path) const {
    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(&xex_.certificate.size), sizeof(uint32_t));

    out.write(reinterpret_cast<const char*>(&xex_.certificate.time_date_1), sizeof(uint32_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.time_date_2), sizeof(uint32_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.title_id), sizeof(uint32_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.platform), sizeof(uint16_t));

    out.write(reinterpret_cast<const char*>(&xex_.certificate.executable_type), sizeof(uint8_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.page_size), sizeof(uint8_t));

    out.write(reinterpret_cast<const char*>(&xex_.certificate.minimum_version), sizeof(uint32_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.maximum_version), sizeof(uint32_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.allowed_media), sizeof(uint32_t));

    out.write(reinterpret_cast<const char*>(&xex_.certificate.certificate_type), sizeof(uint8_t));
    out.write(reinterpret_cast<const char*>(&xex_.certificate.title_flags), sizeof(uint8_t));

    out.write(reinterpret_cast<const char*>(xex_.certificate.lan_key.data()), 20);
    out.write(reinterpret_cast<const char*>(xex_.certificate.signature_key.data()), 20);
    out.write(reinterpret_cast<const char*>(xex_.certificate.signature.data()), 256);

    out.close();
    return true;
}

bool Xex2Modifier::dump_opt_header(XexOptHeaderId id, const std::string& output_path) const {
    for (const auto& opt_header : xex_.opt_headers) {
        if (opt_header.id == id) {
            std::ofstream out(output_path, std::ios::binary);
            if (!out) {
                return false;
            }

            uint32_t header_id = static_cast<uint32_t>(id);
            out.write(reinterpret_cast<const char*>(&header_id), sizeof(uint32_t));
            out.write(reinterpret_cast<const char*>(&opt_header.size), sizeof(uint32_t));
            out.write(reinterpret_cast<const char*>(opt_header.data.data()), opt_header.size);

            out.close();
            return true;
        }
    }

    return false;
}

bool Xex2Modifier::set_title_id(uint32_t title_id) {
    xex_.certificate.title_id = title_id;
    xex_.execution_info.title_id = title_id;
    return true;
}

bool Xex2Modifier::set_allowed_media(uint32_t allowed_media) {
    xex_.certificate.allowed_media = allowed_media;
    return true;
}

bool Xex2Modifier::set_minimum_version(uint32_t version) {
    xex_.certificate.minimum_version = version;
    return true;
}

bool Xex2Modifier::set_maximum_version(uint32_t version) {
    xex_.certificate.maximum_version = version;
    return true;
}

bool Xex2Modifier::set_media_id(uint32_t media_id) {
    xex_.execution_info.media_id = media_id;
    return true;
}

bool Xex2Modifier::write_xex(const std::string& output_path) const {
    std::ifstream in(xex_.filepath_, std::ios::binary);
    if (!in) {
        return false;
    }

    std::vector<uint8_t> file_data;
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    file_data.resize(file_size);
    in.seekg(0);
    in.read(reinterpret_cast<char*>(file_data.data()), file_size);
    in.close();

    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        return false;
    }

    std::memcpy(file_data.data(), &xex_.header, sizeof(XexHeader));

    uint32_t offset = sizeof(XexHeader);
    for (const auto& opt_header : xex_.opt_headers) {
        std::memcpy(file_data.data() + offset, &opt_header.id, sizeof(uint32_t));
        std::memcpy(file_data.data() + offset + 4, &opt_header.size, sizeof(uint32_t));

        uint32_t data_offset = offset + 8;
        std::memcpy(file_data.data() + data_offset, opt_header.data.data(), opt_header.size);

        offset = ((data_offset + opt_header.size + 0xF) & ~0xF);
    }

    uint32_t cert_offset = xex_.header.security_offset;
    std::memcpy(file_data.data() + cert_offset, &xex_.certificate.size, sizeof(uint32_t));

    uint32_t cert_data_offset = cert_offset + 4;
    std::memcpy(file_data.data() + cert_data_offset, &xex_.certificate.time_date_1, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 4, &xex_.certificate.time_date_2, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 8, &xex_.certificate.title_id, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 12, &xex_.certificate.platform, sizeof(uint16_t));
    std::memcpy(file_data.data() + cert_data_offset + 14, &xex_.certificate.executable_type, sizeof(uint8_t));
    std::memcpy(file_data.data() + cert_data_offset + 15, &xex_.certificate.page_size, sizeof(uint8_t));
    std::memcpy(file_data.data() + cert_data_offset + 16, &xex_.certificate.minimum_version, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 20, &xex_.certificate.maximum_version, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 24, &xex_.certificate.allowed_media, sizeof(uint32_t));
    std::memcpy(file_data.data() + cert_data_offset + 28, &xex_.certificate.certificate_type, sizeof(uint8_t));
    std::memcpy(file_data.data() + cert_data_offset + 29, &xex_.certificate.title_flags, sizeof(uint8_t));
    std::memcpy(file_data.data() + cert_data_offset + 30, xex_.certificate.lan_key.data(), 20);
    std::memcpy(file_data.data() + cert_data_offset + 50, xex_.certificate.signature_key.data(), 20);
    std::memcpy(file_data.data() + cert_data_offset + 70, xex_.certificate.signature.data(), 256);

    out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
    out.close();

    return true;
}

}
