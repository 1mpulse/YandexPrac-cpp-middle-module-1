#include "crypto_guard_ctx.h"

#include <iostream>

namespace CryptoGuard {

class CryptoGuardCtx::Impl
{
public:
    Impl() = default;
    ~Impl() = default;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>())
{

}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{

}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{

}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream)
{
    return "NOT_IMPLEMENTED";
}

}  // namespace CryptoGuard
