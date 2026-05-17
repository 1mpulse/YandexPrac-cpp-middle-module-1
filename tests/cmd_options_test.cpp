#include "cmd_options.h"

#include <gtest/gtest.h>

TEST(ProgramOptions, EncryptLongArgs)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--command", "encrypt",
        "--input", "input.txt",
        "--output", "output.txt",
        "--password", "secret"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, DecryptShortArgs)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--command", "decrypt",
        "-i", "input.txt",
        "-o", "output.txt",
        "-p", "secret"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ChecksumClearsPassword)
{
    CryptoGuard::ProgramOptions options;

    const char* argv1[] = {
        "app",
        "--command", "encrypt",
        "--input", "input.txt",
        "--output", "output.txt",
        "--password", "secret"
    };

    options.Parse(std::size(argv1), const_cast<char**>(argv1));
    ASSERT_EQ(options.GetPassword(), "secret");

    const char* argv2[] = {
        "app",
        "--command", "checksum",
        "--input", "input.txt",
        "--output", "hash.txt"
    };

    options.Parse(std::size(argv2), const_cast<char**>(argv2));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "hash.txt");
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, NoCommand)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--input", "input.txt",
        "--output", "output.txt"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, ChecksumWithoutOutput)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--command", "checksum",
        "--input", "input.txt"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, EncryptWithoutPassword)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--command", "encrypt",
        "--input", "input.txt",
        "--output", "output.tar.gz"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.tar.gz");
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, UnknownCommand)
{
    CryptoGuard::ProgramOptions options;

    const char* argv[] = {
        "app",
        "--command", "zip",
        "--input", "input.txt",
        "--output", "output.zip"
    };

    options.Parse(std::size(argv), const_cast<char**>(argv));

    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}