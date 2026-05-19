#include <algorithm>
#include <array>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

#include "crypto_guard_ctx.h"

namespace CryptoGuard {

class CryptoGuardCtx::PImpl
{
public:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    PImpl() = default;
    ~PImpl() = default;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password)
    {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>())
{
    OpenSSL_add_all_algorithms();
}

CryptoGuardCtx::~CryptoGuardCtx()
{
    EVP_cleanup();
}

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream)
{
    return pImpl_->CalculateChecksum(inStream);
}

void CryptoGuardCtx::PImpl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    if (!inStream.good())
    {
        throw std::runtime_error{"Bad input"};
    }

    if (!outStream.good())
    {
        throw std::runtime_error{"Bad output"};
    }

    auto params = CreateChiperParamsFromPassword(password);
    std::string input((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());

    if (!inStream.good())
    {
        throw std::runtime_error{"Bad input #2"};
    }

    int outLen = 0;
    int tmpLen = 0;
    std::vector<unsigned char> outBuf(input.size() + EVP_MAX_BLOCK_LENGTH);

    auto *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        throw std::runtime_error{"Failed to create EVP_CIPHER_CTX"};
    }

    if (EVP_EncryptInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_EncryptInit_ex"};
    }

    if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, reinterpret_cast<const unsigned char *>(input.data()), static_cast<int>(input.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_EncryptUpdate"};
    }

    if (EVP_EncryptFinal_ex(ctx, outBuf.data() + outLen, &tmpLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_EncryptFinal_ex"};
    }

    outLen += tmpLen;
    EVP_CIPHER_CTX_free(ctx);

    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

    if (!outStream.good())
    {
        throw std::runtime_error{"Bad output #3"};
    }
}

void CryptoGuardCtx::PImpl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    if (!inStream.good())
    {
        throw std::runtime_error{"Bad input"};
    }

    if (!outStream.good())
    {
        throw std::runtime_error{"Bad output"};
    }

    auto params = CreateChiperParamsFromPassword(password);
    std::string input((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());

    if (!inStream.good())
    {
        throw std::runtime_error{"Bad input #2"};
    }

    int outLen = 0;
    int tmpLen = 0;
    std::vector<unsigned char> outBuf(input.size() + EVP_MAX_BLOCK_LENGTH);

    auto *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        throw std::runtime_error{"Failed to create EVP_CIPHER_CTX"};
    }

    if (EVP_DecryptInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_DecryptInit_ex"};
    }

    if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, reinterpret_cast<const unsigned char *>(input.data()), static_cast<int>(input.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_DecryptUpdate"};
    }

    if (EVP_DecryptFinal_ex(ctx, outBuf.data() + outLen, &tmpLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error{"Failed EVP_DecryptFinal_ex"};
    }

    outLen += tmpLen;
    EVP_CIPHER_CTX_free(ctx);

    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

    if (!outStream.good())
    {
        throw std::runtime_error{"Bad output #3"};
    }
}

std::string CryptoGuardCtx::PImpl::CalculateChecksum(std::iostream &inStream)
{
    return "NOT_IMPLEMENTED";
}

}  // namespace CryptoGuard
