#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <string_view>

namespace xexemu {

constexpr uint32_t XEX_MAGIC = 0x58455832;  // "XEX2"

enum class XexHeaderFlags : uint32_t {
    None = 0,
    Encrypted = 0x00000001,
    Compressed = 0x00000002,
    AlignedData = 0x00000004,
    DevKit = 0x00000008,
    Retail = 0x00000010,
    Profile = 0x00000020,
    Multidisc = 0x00000040,
};

enum class XexOptHeaderId : uint32_t {
    Reserved = 0x00000000,
    ResourceInfo = 0x00000100,
    FileFormatInfo = 0x00000FF5,
    EntryPoint = 0x00000001,
    ImageBaseAddress = 0x00000200,
    ImageBaseSize = 0x00000401,
    DefaultStackSize = 0x00000800,
    PEImageDigest = 0x00001001,
    SessionID = 0x00002000,
    AllowedMediaTypes = 0x00003000,
    EncryptionKey = 0x00004000,
    AlternateTitleIds = 0x00005000,
    LanKey = 0x00006000,
    Xbox360Logo = 0x00007001,
    Xbox1Logo = 0x00008001,
    OnlineServiceIds = 0x00009000,
    DeviceIdKey = 0x0000A000,
    ExecutionInfo = 0x00000FF6,
    StackInfo = 0x00000FF7,
    OriginalPEName = 0x00000FF8,
    OriginalFileName = 0x00000FF9,
    OriginalFileSn = 0x00000FFA,
    OriginalUnencryptedHash = 0x00000FFB,
    AlternateExeInfo = 0x00000FFC,
    ServiceIdList = 0x00000FFD,
};

struct XexHeader {
    uint32_t magic;
    uint32_t header_size;
    uint32_t security_offset;
    uint32_t header_count;
};

struct XexOptHeader {
    XexOptHeaderId id;
    uint32_t size;
    std::vector<uint8_t> data;
};

struct XexResourceInfo {
    uint32_t offset;
    uint32_t size;
    uint32_t flags;
    uint32_t title_id;
};

struct PeFileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct XexExecutionInfo {
    uint32_t media_id;
    uint32_t version;
    uint32_t base_version;
    uint32_t title_id;
    uint8_t platform;
    uint8_t executable_type;
    uint8_t disc_number;
    uint8_t disc_count;
    uint32_t save_game_id;
};

struct XexCertificate {
    uint32_t size;
    uint32_t time_date_1;
    uint32_t time_date_2;
    uint32_t title_id;
    uint16_t platform;
    uint8_t executable_type;
    uint8_t page_size;
    uint32_t minimum_version;
    uint32_t maximum_version;
    uint32_t allowed_media;
    uint8_t certificate_type;
    uint8_t title_flags;
    std::array<uint8_t, 20> lan_key;
    std::array<uint8_t, 20> signature_key;
    std::array<uint8_t, 256> signature;
};

struct XexFileFormatInfo {
    uint32_t encryption_type;
    uint32_t compression_type;
    uint32_t encryption_flags;
    uint32_t block_count;
    uint64_t image_size;
    uint32_t image_base;
    uint32_t image_size_high;
    uint32_t image_base_high;
};

struct XexSecurityHeader {
    uint32_t id;
    uint32_t size;
    std::vector<uint8_t> data;
};

struct Xex2 {
    XexHeader header;
    std::vector<XexOptHeader> opt_headers;
    XexCertificate certificate;
    std::vector<XexSecurityHeader> security_headers;
    XexExecutionInfo execution_info;
    XexFileFormatInfo file_format_info;
    std::vector<XexResourceInfo> resource_infos;
    std::vector<uint8_t> image_data;
    bool is_encrypted;
    bool is_compressed;
    std::string filepath_;
};

class Xex2Loader {
public:
    explicit Xex2Loader(const Xex2& xex);
    bool load();
    bool resolve_imports();
    bool initialise_tls();
    bool map_segments();
    bool parse_exception_directory();

private:
    const Xex2& xex_;
    std::vector<uint8_t> decrypted_image_;
    bool is_loaded_;
};

class Xex2Validator {
public:
    explicit Xex2Validator(const Xex2& xex);

    bool verify_hypervisor_signature() const;
    bool verify_kernel_load_checks() const;
    bool verify_certificate_chain() const;
    bool verify_media_restrictions() const;

    struct VerificationResult {
        bool hypervisor_valid;
        bool kernel_valid;
        bool certificate_valid;
        bool media_valid;
        std::string error_message;
    };

    VerificationResult full_verification() const;

private:
    const Xex2& xex_;
};

Xex2 parse_xex2(std::string_view filepath);

class Xex2Modifier {
public:
    explicit Xex2Modifier(Xex2& xex);

    bool dump_header(const std::string& output_path) const;
    bool dump_certificate(const std::string& output_path) const;
    bool dump_opt_header(XexOptHeaderId id, const std::string& output_path) const;

    bool set_title_id(uint32_t title_id);
    bool set_allowed_media(uint32_t allowed_media);
    bool set_minimum_version(uint32_t version);
    bool set_maximum_version(uint32_t version);
    bool set_media_id(uint32_t media_id);

    bool write_xex(const std::string& output_path) const;

private:
    Xex2& xex_;
};

}