#pragma once

#include <stdexcept>
#include <string>
#include <string_view>
#include <cstdint>

namespace xexemu {

class XexException : public std::runtime_error {
public:
    explicit XexException(std::string_view message) : std::runtime_error(std::string(message)) {}
    virtual ~XexException() = default;
};

class XexParsingException : public XexException {
public:
    explicit XexParsingException(std::string_view message) : XexException(message) {}
};

class XexValidationException : public XexException {
public:
    explicit XexValidationException(std::string_view message) : XexException(message) {}
};

class XexLoaderException : public XexException {
public:
    explicit XexLoaderException(std::string_view message) : XexException(message) {}
};

class XexModificationException : public XexException {
public:
    explicit XexModificationException(std::string_view message) : XexException(message) {}
};

class XexIOException : public XexException {
public:
    explicit XexIOException(std::string_view message) : XexException(message) {}
};

class InvalidMagicException : public XexParsingException {
public:
    explicit InvalidMagicException(std::string_view expected, std::string_view found)
        : XexParsingException(std::string("invalid magic number: expected ") + std::string(expected) + 
                              ", found " + std::string(found)) {}
};

class InsufficientDataException : public XexParsingException {
public:
    explicit InsufficientDataException(std::string_view field, size_t expected, size_t actual)
        : XexParsingException(std::string("insufficient data for field ") + std::string(field) + 
                              ": expected " + std::to_string(expected) + " bytes, got " + std::to_string(actual)) {}
};

class CorruptHeaderException : public XexParsingException {
public:
    explicit CorruptHeaderException(std::string_view header_type, std::string_view reason)
        : XexParsingException(std::string("corrupt ") + std::string(header_type) + 
                              " header: " + std::string(reason)) {}
};

class InvalidOffsetException : public XexParsingException {
public:
    explicit InvalidOffsetException(std::string_view field, uint32_t offset, size_t file_size)
        : XexParsingException(std::string("invalid offset for ") + std::string(field) + 
                              ": 0x" + std::to_string(offset) + " exceeds file size " + std::to_string(file_size)) {}
};

class SignatureVerificationException : public XexValidationException {
public:
    explicit SignatureVerificationException(std::string_view reason)
        : XexValidationException(std::string("signature verification failed: ") + std::string(reason)) {}
};

class CertificateValidationException : public XexValidationException {
public:
    explicit CertificateValidationException(std::string_view field, std::string_view reason)
        : XexValidationException(std::string("certificate validation failed for ") + std::string(field) + 
                                  ": " + std::string(reason)) {}
};

class MediaRestrictionException : public XexValidationException {
public:
    explicit MediaRestrictionException(uint32_t allowed_media)
        : XexValidationException(std::string("media restriction violation: allowed_media=0x") + 
                                  std::to_string(allowed_media)) {}
};

class VersionRestrictionException : public XexValidationException {
public:
    explicit VersionRestrictionException(uint32_t min_ver, uint32_t max_ver, uint32_t system_ver)
        : XexValidationException(std::string("version restriction violation: requires ") + 
                                  std::to_string(min_ver) + "-" + std::to_string(max_ver) + 
                                  ", system is " + std::to_string(system_ver)) {}
};

class PeCorruptException : public XexLoaderException {
public:
    explicit PeCorruptException(std::string_view reason)
        : XexLoaderException(std::string("corrupt PE image: ") + std::string(reason)) {}
};

class InvalidPeMagicException : public PeCorruptException {
public:
    explicit InvalidPeMagicException(uint32_t magic)
        : PeCorruptException(std::string("invalid PE magic: 0x") + std::to_string(magic)) {}
};

class SectionMappingException : public XexLoaderException {
public:
    explicit SectionMappingException(std::string_view reason)
        : XexLoaderException(std::string("section mapping failed: ") + std::string(reason)) {}
};

class ImportResolutionException : public XexLoaderException {
public:
    explicit ImportResolutionException(std::string_view import_name, std::string_view reason)
        : XexLoaderException(std::string("import resolution failed for ") + std::string(import_name) + 
                             ": " + std::string(reason)) {}
};

class TlsInitialisationException : public XexLoaderException {
public:
    explicit TlsInitialisationException(std::string_view reason)
        : XexLoaderException(std::string("TLS initialisation failed: ") + std::string(reason)) {}
};

class HeaderModificationException : public XexModificationException {
public:
    explicit HeaderModificationException(std::string_view field, std::string_view reason)
        : XexModificationException(std::string("failed to modify ") + std::string(field) + 
                                    ": " + std::string(reason)) {}
};

class WriteException : public XexModificationException {
public:
    explicit WriteException(std::string_view filepath, std::string_view reason)
        : XexModificationException(std::string("failed to write to ") + std::string(filepath) + 
                                    ": " + std::string(reason)) {}
};

class FileOpenException : public XexIOException {
public:
    explicit FileOpenException(std::string_view filepath, std::string_view reason)
        : XexIOException(std::string("failed to open ") + std::string(filepath) + 
                         ": " + std::string(reason)) {}
};

class FileReadException : public XexIOException {
public:
    explicit FileReadException(std::string_view filepath, size_t expected, size_t actual)
        : XexIOException(std::string("failed to read from ") + std::string(filepath) + 
                         ": expected " + std::to_string(expected) + " bytes, got " + std::to_string(actual)) {}
};

}
