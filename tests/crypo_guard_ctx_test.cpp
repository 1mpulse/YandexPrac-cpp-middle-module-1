#include <gtest/gtest.h>

#include <sstream>
#include <string>

#include "crypto_guard_ctx.h"

TEST(CryptoGuardEncrypt, Test1)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello world!");
    std::stringstream output;

    ctx.EncryptFile(input, output, "password");

    EXPECT_FALSE(output.str().empty());
}

TEST(CryptoGuardEncrypt, Test2)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello world!");
    input.setstate(std::ios::badbit);

    std::stringstream output;

    ASSERT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}

TEST(CryptoGuardEncrypt, Test3)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello world!");

    std::stringstream output;
    output.setstate(std::ios::badbit);

    EXPECT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}
