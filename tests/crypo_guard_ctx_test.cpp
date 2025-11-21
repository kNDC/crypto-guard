#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <string>

// Tests for encryption
TEST(CryptoGuard_Tests, EncryptExceptionInput)
{
    // A non-existent path to force an exception
    std::fstream in("::");
    std::stringstream out{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(in, out, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, EncryptExceptionOutput)
{
    // A non-existent path to force an exception
    std::stringstream in{};
    std::fstream out("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(in, out, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, EncryptEmptyFile)
{
    std::stringstream in("");
    std::stringstream out{};

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(in, out, "0123456789");
}

TEST(CryptoGuard_Tests, EncryptDecryptComposite)
{
    std::string s = "This is a test string";
    std::string password = "isbvisvjnsivbnv";

    std::stringstream in(s);
    std::stringstream mid;
    std::stringstream out;

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(in, mid, password);
    ctx.DecryptFile(mid, out, password);

    EXPECT_EQ(s, out.str());
}

// Tests for decryption
TEST(CryptoGuard_Tests, DecryptExceptionInput)
{
    // A non-existent path to force an exception
    std::fstream in("::");
    std::stringstream out{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(in, out, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, DecryptExceptionOutput)
{
    // A non-existent path to force an exception
    std::stringstream in{};
    std::fstream out("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(in, out, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, DecryptEmptyFile)
{
    // An empty string cannot be decrypted
    using namespace std::string_literals;

    std::stringstream in("");
    std::stringstream out{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(in, out, "1234"), 
        std::runtime_error);
}

// Tests for checksum calculations
TEST(CryptoGuard_Tests, ChecksumCalculationException)
{
    using namespace std::string_literals;

    // A non-existent path to force an exception
    std::fstream in("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.CalculateChecksum(in), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, ChecksumCalculation)
{
    using namespace std::string_literals;

    std::string s = "This is a test string";
    std::stringstream in(s);

    CryptoGuard::CryptoGuardCtx ctx;

    EXPECT_EQ(ctx.CalculateChecksum(in), 
        "717ac506950da0ccb6404cdd5e7591f72018a20cbca27c8a423e9c9e5626ac61"s);
    
    in = std::stringstream("This is another test string"s);
    EXPECT_EQ(ctx.CalculateChecksum(in), 
        "e3786ae2f5f45065e224983439d81c5ebcaa9dcd4d37a0eeda99e53c12544cd3"s);
    
    in = std::stringstream("This is yet another test string"s);
    EXPECT_EQ(ctx.CalculateChecksum(in), 
        "ee8e26616612760e853ad17703c6c977fd3958bc088269e595fb4d280c5c74ba"s);
}