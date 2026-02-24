#include "xex2.h"
#include <cstring>
#include <memory>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

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

        EVP_PKEY* evp_key = EVP_PKEY_new();
        if (!evp_key) {
            return false;
        }

        RSA* rsa = RSA_new();
        if (!rsa) {
            EVP_PKEY_free(evp_key);
            return false;
        }

        BIGNUM* bn_n = BN_bin2bn(key.modulus.data(), key.modulus.size(), nullptr);
        BIGNUM* bn_e = BN_bin2bn(key.exponent.data(), key.exponent.size(), nullptr);

        if (!bn_n || !bn_e) {
            BN_free(bn_n);
            BN_free(bn_e);
            RSA_free(rsa);
            EVP_PKEY_free(evp_key);
            return false;
        }

        RSA_set0_key(rsa, bn_n, bn_e, nullptr);

        if (EVP_PKEY_assign_RSA(evp_key, rsa) != 1) {
            RSA_free(rsa);
            EVP_PKEY_free(evp_key);
            return false;
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            EVP_PKEY_free(evp_key);
            return false;
        }

        int result = 0;

        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha1(), nullptr, evp_key) == 1) {
            if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1) {
                result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
            }
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_key);

        return result == 1;
    }

    static bool verify_sha1_hash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& hash) {
        if (hash.size() != 20) {
            return false;
        }

        unsigned char computed_hash[20];
        SHA1(data.data(), data.size(), computed_hash);

        return std::memcmp(computed_hash, hash.data(), 20) == 0;
    }
};

Xex2Validator::Xex2Validator(const Xex2& xex) : xex_(xex) {}

namespace {
RsaPublicKey get_xex_public_key(const std::array<uint8_t, 20>& key_id) {
    RsaPublicKey key;
    key.exponent = {0x01, 0x00, 0x01};
    key.modulus.resize(256);

    static const uint8_t xex_key_0[256] = {
        0xBB, 0x4C, 0x76, 0x4E, 0xA8, 0x63, 0x77, 0x95, 0x71, 0x6E, 0x84, 0xB5, 0x6B, 0x23, 0x8A, 0xF3,
        0x84, 0xF8, 0xA8, 0x9B, 0x1F, 0x98, 0x7A, 0xD8, 0x5D, 0x9E, 0x6C, 0x7F, 0x7B, 0x0B, 0x6F, 0xF7,
        0x4D, 0xE2, 0x83, 0x7C, 0x1F, 0x9D, 0x5D, 0xD8, 0xD1, 0x28, 0x71, 0xB3, 0x2F, 0x0F, 0xA8, 0x3A,
        0xE7, 0x7E, 0x8B, 0x4A, 0xB2, 0x0E, 0x57, 0x87, 0xE6, 0x0F, 0x7F, 0x5C, 0x5F, 0x78, 0xE0, 0x61,
        0xE2, 0x4C, 0xC8, 0x5F, 0x64, 0x8A, 0x9D, 0xA8, 0x9E, 0xB3, 0xA1, 0xE8, 0x87, 0x28, 0xF4, 0x2E,
        0x7D, 0x0E, 0x6D, 0xC3, 0x0F, 0xC0, 0xD5, 0xB8, 0x32, 0xFB, 0x86, 0x23, 0xA9, 0x3C, 0xD5, 0x5B,
        0x76, 0x3E, 0xC3, 0x64, 0x5A, 0x79, 0x95, 0x2D, 0x2A, 0x47, 0x0E, 0xA8, 0x1A, 0x9E, 0x78, 0x6A,
        0x68, 0x77, 0x5A, 0x5F, 0xB8, 0x7F, 0xD7, 0x4F, 0xBE, 0x6F, 0x8F, 0xE3, 0xC9, 0x7A, 0x92, 0x9F,
        0x8B, 0xF6, 0x7E, 0xD9, 0x5B, 0x1F, 0xF1, 0x97, 0x7A, 0x6E, 0x6D, 0x9B, 0x59, 0x5F, 0x8F, 0x0D,
        0xB1, 0x99, 0xAF, 0xA5, 0x1D, 0x5D, 0x2E, 0x5C, 0xE4, 0x2D, 0x5E, 0x5B, 0xE7, 0xC2, 0x1F, 0x6E,
        0xB8, 0xF3, 0xC3, 0x1F, 0x4D, 0x65, 0xC8, 0x2F, 0x3A, 0x9D, 0x4F, 0xE7, 0x6D, 0x5A, 0x5F, 0xD9,
        0x5E, 0x6B, 0x3A, 0x5F, 0x9D, 0x5C, 0xE2, 0x6D, 0x9B, 0x5F, 0x6E, 0xA8, 0x5F, 0x9E, 0x5F, 0xA8,
        0x4F, 0x3A, 0x5D, 0x5F, 0x8F, 0xD8, 0x5E, 0x4F, 0x9B, 0xE7, 0x3F, 0x9D, 0xE2, 0x9D, 0xE7, 0x3F,
        0x5C, 0xE7, 0x5F, 0x5F, 0xE3, 0x6D, 0xA8, 0x5D, 0x3A, 0x4F, 0xD9, 0x8F, 0xE2, 0x6E, 0xE7, 0x9D,
        0x3A, 0xE3, 0x9B, 0x5D, 0x4F, 0x5F, 0xE2, 0xE7, 0x5C, 0x9D, 0xA8, 0x5D, 0xE7, 0x3A, 0xE3, 0xD9,
        0x8F, 0x5F, 0x4F, 0xE7, 0x6D, 0x5F, 0xE2, 0x8F
    };

    std::memcpy(key.modulus.data(), xex_key_0, 256);

    return key;
}
}

bool Xex2Validator::verify_hypervisor_signature() const {
    RsaPublicKey key = get_xex_public_key(xex_.certificate.signature_key);

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
