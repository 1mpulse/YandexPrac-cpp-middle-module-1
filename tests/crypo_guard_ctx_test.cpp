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

TEST(CryptoGuardDecrypt, Test1)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream encrypted;
    std::stringstream decrypted;
    std::stringstream input("hello world!");

    ctx.EncryptFile(input, encrypted, "password");

    std::stringstream encryptedInput(encrypted.str());
    ctx.DecryptFile(encryptedInput, decrypted, "password");

    EXPECT_EQ(decrypted.str(), "hello world!");
}

TEST(CryptoGuardDecrypt, Test2)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream output;
    std::stringstream input("؆W�I6/M���᪈�PM'tV̽���?~�");

    input.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.DecryptFile(input, output, "1234"), std::runtime_error);
}

TEST(CryptoGuardDecrypt, Test3)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream output;
    std::stringstream encrypted;
    std::stringstream input("hello world!");

    output.setstate(std::ios::badbit);

    ctx.EncryptFile(input, encrypted, "password");

    std::stringstream encryptedInput(encrypted.str());

    EXPECT_THROW(ctx.DecryptFile(encryptedInput, output, "password"), std::runtime_error);
}

TEST(CryptoGuardCalculateChecksum, Test1)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello world!");

    EXPECT_EQ(ctx.CalculateChecksum(input),
              "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9");
}

TEST(CryptoGuardCalculateChecksum, Test2)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("");

    EXPECT_EQ(ctx.CalculateChecksum(input),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCalculateChecksum, Test3)
{
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello world!");
    input.setstate(std::ios::badbit);

    EXPECT_THROW(ctx.CalculateChecksum(input), std::runtime_error);
}
