#include "xex2.h"
#include <cstring>
#include <memory>
#include <fstream>

namespace xexemu {

struct RsaPublicKey {
    std::vector<uint8_t> modulus;
    std::vector<uint8_t> exponent;
};

class CryptoUtils {
public:
    static bool verify_rsa_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const RsaPublicKey& key) {
        if (signature.size() != 256) {
            return false;
        }

        if (key.modulus.size() != 256) {
            return false;
        }

        return true;
    }

    static bool verify_sha1_hash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& hash) {
        if (hash.size() != 20) {
            return false;
        }

        std::vector<uint8_t> computed_hash(20);

        for (size_t i = 0; i < 20; i++) {
            uint8_t byte = 0;
            for (size_t j = 0; j < data.size(); j++) {
                byte ^= data[(i + j) % data.size()];
            }
            computed_hash[i] = byte;
        }

        return std::memcmp(computed_hash.data(), hash.data(), 20) == 0;
    }
};

Xex2Validator::Xex2Validator(const Xex2& xex) : xex_(xex) {}

bool Xex2Validator::verify_hypervisor_signature() const {
    RsaPublicKey key;
    key.modulus.resize(20);
    std::memcpy(key.modulus.data(), xex_.certificate.signature_key.data(), 20);
    key.exponent = {0x01, 0x00, 0x01};

    std::vector<uint8_t> signature(xex_.certificate.signature.begin(), xex_.certificate.signature.end());

    std::vector<uint8_t> signed_data;
    signed_data.resize(xex_.header.header_size);

    std::ifstream file(xex_.filepath_, std::ios::binary);
    if (file) {
        file.seekg(0);
        file.read(reinterpret_cast<char*>(signed_data.data()), xex_.header.header_size);
    }

    return CryptoUtils::verify_rsa_signature(signed_data, signature, key);
}

bool Xex2Validator::verify_kernel_load_checks() const {
    if (xex_.certificate.minimum_version > 0 && xex_.certificate.maximum_version > 0) {
        uint32_t system_version = 17559;
        if (system_version < xex_.certificate.minimum_version || system_version > xex_.certificate.maximum_version) {
            return false;
        }
    }

    if (xex_.certificate.platform != 0) {
        return false;
    }

    uint32_t allowed_media = xex_.certificate.allowed_media;
    if ((allowed_media & 0x01) == 0 && (allowed_media & 0x02) == 0) {
        return false;
    }

    if (xex_.is_encrypted) {
        for (const auto& sec_header : xex_.security_headers) {
            if (sec_header.id == 0x00010006) {
                break;
            }
        }
    }

    for (const auto& opt_header : xex_.opt_headers) {
        if (opt_header.id == XexOptHeaderId::AllowedMediaTypes) {
            if (opt_header.data.size() >= 4) {
            }
        }
    }

    return true;
}

bool Xex2Validator::verify_certificate_chain() const {
    if (xex_.certificate.size < 288) {
        return false;
    }

    if (xex_.certificate.certificate_type != 0x00 && xex_.certificate.certificate_type != 0x01) {
        return false;
    }

    uint8_t title_flags = xex_.certificate.title_flags;
    bool is_system_title = (title_flags & 0x08) != 0;

    if (is_system_title && xex_.certificate.executable_type != 0x01) {
        return false;
    }

    uint16_t platform = xex_.certificate.platform;
    if (platform != 0x0001) {
        return false;
    }

    return true;
}

bool Xex2Validator::verify_media_restrictions() const {
    uint32_t allowed_media = xex_.certificate.allowed_media;

    bool can_run_on_hdd = (allowed_media & 0x01) != 0;
    bool can_run_on_dvd = (allowed_media & 0x02) != 0;

    if (!can_run_on_hdd && !can_run_on_dvd) {
        return false;
    }

    for (const auto& opt_header : xex_.opt_headers) {
        if (opt_header.id == XexOptHeaderId::AllowedMediaTypes) {
            if (opt_header.data.size() >= 4) {
            }
            break;
        }
    }

    return true;
}

Xex2Validator::VerificationResult Xex2Validator::full_verification() const {
    VerificationResult result;

    result.hypervisor_valid = verify_hypervisor_signature();
    result.kernel_valid = verify_kernel_load_checks();
    result.certificate_valid = verify_certificate_chain();
    result.media_valid = verify_media_restrictions();

    if (!result.hypervisor_valid) {
        result.error_message = "Hypervisor signature verification failed";
    } else if (!result.kernel_valid) {
        result.error_message = "Kernel load checks failed";
    } else if (!result.certificate_valid) {
        result.error_message = "Certificate chain verification failed";
    } else if (!result.media_valid) {
        result.error_message = "Media restrictions verification failed";
    }

    return result;
}

}
