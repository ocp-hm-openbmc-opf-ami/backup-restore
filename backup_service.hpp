

/* ****************************************************************
*
* Backup and Restore
* backup_service.hpp
*
* @brief dbus service for Backup and Restore
*
* Author: Lucas Panayioto lucasp@ami.com
*
*****************************************************************/
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>


//Error Logging
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>



#define BR_KEY_IDENTIFIER "$BRAKIDF$"
#define BR_IV_IDENTIFIER "$BRAIVIDF$"
#define Image_size 0x4000000
#define BR_KEY_OFFSET 0x3200
#define BR_IV_OFFSET  0x3400
#define BR_KID_SIZE   10
#define BR_IVID_SIZE   11
#define erase_blk_size 0x10000
#define GET_ENCRYPT_KEY 0
#define GET_INITIAL_VECTOR 1

constexpr auto aesKeyFile = "/etc/backups/AESKey";
constexpr auto aesIVFile = "/etc/backups/AESIV";
constexpr auto AES_MAX_KEY_LENGTH = 32;  // 256 bits
constexpr auto AES_MAX_IV_LENGTH = 16;   // 128 bits
constexpr auto AES_MAX_HEX_KEY_LENGTH = 44;
constexpr auto AES_MAX_HEX_IV_LENGTH = 24;

unsigned char aesKey[AES_MAX_KEY_LENGTH];
unsigned char aesIV[AES_MAX_IV_LENGTH];

using::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void Initialize_Key();
template <typename... ArgTypes> std::vector <std::string> executeCmd(const char * path, ArgTypes && ... tArgs)
{
    std::vector <std::string> stdOutput;
    boost::process::ipstream stdOutStream;
    boost::process::child execProg(path, const_cast <char*> (tArgs) ..., 
        boost::process::std_out > stdOutStream);
    std::string stdOutLine;

    while (stdOutStream && std::getline(stdOutStream, stdOutLine) && !stdOutLine.empty())
    {
        stdOutput.emplace_back(stdOutLine);
    }

    execProg.wait();

    int retCode = execProg.exit_code();

    if (retCode)
    {
        phosphor::logging::log <phosphor::logging::level::ERR> ("Command execution failed", 
            phosphor::logging::entry("PATH=%d", path), 
            phosphor::logging::entry("RETURN_CODE:%d", retCode));
        phosphor::logging::elog <InternalFailure> ();

    }

    return stdOutput;
}

/**
 * @brief Base64 encode a character string.
 *
 * @param[out] outbuf - Pointer to the buffer to store the base64-encoded data.
 * @param[in]  string - Pointer to the input data that needs to be encoded.
 * @param[in]  outlen - Length of the output buffer (`outbuf`).
 * @param[in]  inlen  - Length of the input data (`string`).
 */
void Encode64nChar(char* outbuf, const char* string, int outlen, int inlen) 
{
    if (string != nullptr && outbuf != nullptr && outlen != 0) 
    {
        if (inlen == 0) 
        {
            *outbuf = '\0';
            return;
        }
        BIO* bio = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        bio = BIO_push(bio, bmem);

        BIO_write(bio, string, inlen);
        BIO_flush(bio);

        int encodedLength = BIO_read(bmem, outbuf, outlen);

        outbuf[encodedLength] = '\0';

        BIO_free_all(bio);
    }
}

/**
 * @brief Base64 decode a character string to binary data.
 *
 * @param[out] outbuf - Pointer to the buffer to store the decoded binary data.
 * @param[in]  string - Pointer to the base64-encoded input data.
 * @param[in]  outlen - Length of the output buffer (`outbuf`).
 * @param[in]  inlen  - Length of the base64-encoded input data (`string`).
 */

void Decode64binary(char* outbuf, const char* string, int outlen, int inlen) 
{
    if (string != nullptr && outbuf != nullptr && outlen != 0) 
    {
        if (inlen == 0) 
        {
            *outbuf = '\0';
            return;
        }

        BIO* bio = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf(string, inlen);
        bio = BIO_push(bio, bmem);

        int decodedLength = BIO_read(bio, outbuf, outlen);

        outbuf[decodedLength] = '\0';

        BIO_free_all(bio);
    }
}

/**
 * @brief Retrieve or generate an AES key from/to a file.
 *
 * @param[in]  filename    - The name of the file containing the AES key.
 * @param[out] key         - Pointer to the buffer to store the AES key.
 * @param[in]  key_size    - The size of the AES key in bytes.
 * @param[in]  hex_key_size - The size of the hex-encoded key (including null terminator).
 *
 * @return 0 on success, -1 on failure.
 */

int AES_GetKeyFromFile(const char* filename, unsigned char* key, int key_size, int hex_key_size)
{
    std::ifstream fp(filename);
    char* hex_data = new char[hex_key_size + 1];
    int ret = -1;

    if (fp.is_open())
    {
        if (fp.read(hex_data, hex_key_size))
        {
            hex_data[hex_key_size] = '\0';
            Decode64binary(reinterpret_cast<char*>(key), hex_data, key_size, hex_key_size);
            std::cerr << "Successfully read the value of key." << std::endl;
            ret = 0;
            fp.close();
        }
    }
    else
    {
        // Generate cryptography strong pseudo-random bytes for key
        if (!RAND_bytes(key, key_size))
        {
            std::cerr << "ERROR: RAND_bytes - Unable to generate key" << std::endl;
            delete[] hex_data;
            return -1;
        }

        Encode64nChar(hex_data, reinterpret_cast<const char*>(key), hex_key_size, key_size);

        std::ofstream fp(filename);
        if (!fp.is_open())
        {
            std::cerr << "Unable to open file for writing: " << filename << std::endl;
            delete[] hex_data;
            return -1;
        }

        if (chmod(filename, S_IRUSR | S_IWUSR) != 0) {
            std::cerr << "ERROR: Unable to change the permission for " << filename << std::endl;
            delete[] hex_data;
            fp.close();
            return -1;
        }

        fp.write(hex_data, hex_key_size);
        std::cout << filename << " file not found, Generating new random key" << std::endl;
        fp.close();
        ret = 1;
    }

    delete[] hex_data;
    return ret;
}

/**
 * @brief Encrypts a file using AES-256-CBC encryption.
 *
 * @param[in]  filename - back config file name
 *
 * @return The path to the encrypted file on success, an empty string on failure.
 */
std::string encryptFile(const std::string &fileName)
{
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }



    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIV) != 1) {
        std::cerr << "Error setting up cipher parameters" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::ifstream inputFile("/tmp/backup/" + fileName + "_dcrpt.tar", std::ios::binary);
    std::ofstream outputFile("/tmp/backup/" + fileName + ".tar" , std::ios::binary);
    if (!inputFile || !outputFile) {
        std::cerr << "Error opening files" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Encrypt the file
    unsigned char inBuf[1024], outBuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead, bytesEncrypted;

    while ((bytesRead = inputFile.read(reinterpret_cast<char *>(inBuf), sizeof(inBuf)).gcount()) > 0) {
        if (EVP_EncryptUpdate(ctx, outBuf, &bytesEncrypted, inBuf, bytesRead) != 1) {
            std::cerr << "Error encrypting data" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        outputFile.write(reinterpret_cast<const char *>(outBuf), bytesEncrypted);
    }

    if (EVP_EncryptFinal_ex(ctx, outBuf, &bytesEncrypted) != 1) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    outputFile.write(reinterpret_cast<const char *>(outBuf), bytesEncrypted);

    EVP_CIPHER_CTX_free(ctx);

    return ("/tmp/backup/" + fileName + ".tar");
}

/*
 * @brief Decrypts an AES-256-CBC encrypted file.
 *
 * @param[in]  fileName - Backup config file name.
 *
 * @return true on successful decryption, false on failure.
 */

bool decryptFile(const std::string& fileName)
{

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::ifstream inputFile("/tmp/restore/" + fileName + ".tar" , std::ios::binary);
    std::ofstream outputFile("/tmp/restore/" + fileName + "_dcrpt.tar", std::ios::binary);

    if (!inputFile || !outputFile) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    const size_t bufferSize = 1024;
    unsigned char inBuf[bufferSize], outBuf[bufferSize + EVP_MAX_BLOCK_LENGTH];
    int bytesRead, bytesDecrypted;

    while ((bytesRead = inputFile.readsome((char*)inBuf, bufferSize)) > 0)
    {
        if (EVP_DecryptUpdate(ctx, outBuf, &bytesDecrypted, inBuf, bytesRead) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        outputFile.write(reinterpret_cast<const char *>(outBuf), bytesDecrypted);
    }

    if (EVP_DecryptFinal_ex(ctx, outBuf, &bytesDecrypted) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    outputFile.write(reinterpret_cast<const char *>(outBuf), bytesDecrypted);

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    return true;
}



int AES_GetEncryptKey(unsigned char* EncryptKey) 
{
    return AES_GetKeyFromFile(aesKeyFile, EncryptKey, AES_MAX_KEY_LENGTH, AES_MAX_HEX_KEY_LENGTH);
}

int AES_GetInitialVector(unsigned char* IV) 
{
    return AES_GetKeyFromFile(aesIVFile, IV, AES_MAX_IV_LENGTH, AES_MAX_HEX_IV_LENGTH);
}


void Initialize_Key()
{
    if (AES_GetEncryptKey(aesKey) != 0)
    {
        std::cerr << "Error in getting AESKEY" << std::endl;
    }

    if (AES_GetInitialVector(aesIV) != 0)
    {
        std::cerr << "Error in getting AESIV" << std::endl;
    }

}


int sigwrap_open(const char* path, int flags) {
    return open(path, flags);
}

int sigwrap_read(int fd, void* buf, size_t count) {
    return read(fd, buf, count);
}

void sigwrap_close(int fd) {
    close(fd);
}

/*
 * @brief Read AESKey And AESIV from rom.ima
 *
 * @param[in]  flag - Flag name of AESKey or AESIV
 *
 * @return string of Key value on success, an empty string on failure
 */


std::string AES_GetEncryptKeyAndIV(int flag)
{
    int MTDDevId = 0;
    char key_identifier[BR_KID_SIZE] = {0};
    char iv_identifier[BR_IVID_SIZE] = {0};
    int key_length = 0;
    int iv_length = 0;
    int offset = 0;
    unsigned char* OneEBlock = nullptr;
    std::string key;

    OneEBlock = (unsigned char*)malloc(erase_blk_size);
    if (OneEBlock == nullptr) {
        std::cout << "Memory allocation error\n";
        return "";
    }

    MTDDevId = sigwrap_open("/dev/mtd0", O_RDONLY);
    if (MTDDevId < 0) {
        std::cout << "Cannot open mtd raw device MTDDev. Exiting...\n";
        if (MTDDevId >= 0) {
            sigwrap_close(MTDDevId);
            MTDDevId = -1;
        }
        if (OneEBlock != nullptr) {
            free(OneEBlock);
            OneEBlock = nullptr;
        }

        return "";
    }


    if (lseek(MTDDevId, (Image_size - erase_blk_size), SEEK_SET) == -1) {

        std::cout << "lseek MTDDevId error\n";
        if (MTDDevId >= 0) {
            sigwrap_close(MTDDevId);
            MTDDevId = -1;
        }
        if (OneEBlock != nullptr) {
            free(OneEBlock);
            OneEBlock = nullptr;
        }
        return "";
    }

    int ret_sigwrap_read = sigwrap_read(MTDDevId, OneEBlock, erase_blk_size);

    if ( ret_sigwrap_read != erase_blk_size) {
        std::cout << "read MTDDevId error\n";
        if (MTDDevId >= 0) {
            sigwrap_close(MTDDevId);
            MTDDevId = -1;
        }
        if (OneEBlock != nullptr) {
            free(OneEBlock);
            OneEBlock = nullptr;
        }
        return "";
    }


    if(flag == GET_ENCRYPT_KEY)
    {
        offset = erase_blk_size - BR_KEY_OFFSET;

        memcpy(key_identifier, OneEBlock + offset, sizeof(BR_KEY_IDENTIFIER));
        if (strncmp(key_identifier, BR_KEY_IDENTIFIER, sizeof(BR_KEY_IDENTIFIER)) != 0) {
            std::cout << "aes key not found\n";
            if (MTDDevId >= 0) {
                sigwrap_close(MTDDevId);
                MTDDevId = -1;
            }
            if (OneEBlock != nullptr) {
                free(OneEBlock);
                OneEBlock = nullptr;
            }
            return "";
        }


        offset += sizeof(BR_KEY_IDENTIFIER);
        memcpy(&key_length, OneEBlock + offset, sizeof(key_length));
        offset += sizeof(key_length);
        if (key_length != AES_MAX_HEX_KEY_LENGTH + 1) {

            if (MTDDevId >= 0) {
                sigwrap_close(MTDDevId);
                MTDDevId = -1;
            }
            if (OneEBlock != nullptr) {
                free(OneEBlock);
                OneEBlock = nullptr;
            }
            return "";
        }
        std::string temp_key(reinterpret_cast<const char*>(OneEBlock + offset),AES_MAX_HEX_KEY_LENGTH);
        key = temp_key;
    }
    else if(flag == GET_INITIAL_VECTOR)
    {
        offset = erase_blk_size - BR_IV_OFFSET;

        memcpy(iv_identifier, OneEBlock + offset, sizeof(BR_IV_IDENTIFIER));
        if (strncmp(iv_identifier, BR_IV_IDENTIFIER, sizeof(BR_IV_IDENTIFIER)) != 0) {
            std::cout << "aes IV not found\n";
            if (MTDDevId >= 0) {
                sigwrap_close(MTDDevId);
                MTDDevId = -1;
            }
            if (OneEBlock != nullptr) {
                free(OneEBlock);
                OneEBlock = nullptr;
            }
            return "";
        }


        offset += sizeof(BR_IV_IDENTIFIER);
        memcpy(&iv_length, OneEBlock + offset, sizeof(iv_length));
        offset += sizeof(iv_length);
        if (iv_length != AES_MAX_HEX_IV_LENGTH + 1) {
            std::cout << "invalid length " << std::endl;
            if (MTDDevId >= 0) {
                sigwrap_close(MTDDevId);
                MTDDevId = -1;
            }
            if (OneEBlock != nullptr) {
                free(OneEBlock);
                OneEBlock = nullptr;
            }
            return "";
        }
        std::cout << "iv_length" << iv_length << std::endl;
        std::string temp_key(reinterpret_cast<const char*>(OneEBlock + offset), AES_MAX_HEX_IV_LENGTH);
        std::cout << "temp_key" << temp_key << std::endl;
        key = temp_key;
    }
    else {
        std::cout << "only key or IV can be loaded \n";
        if (OneEBlock != nullptr) {
            free(OneEBlock);
            OneEBlock = nullptr;
        }

        return "";
    }


    if (OneEBlock != nullptr) {
        free(OneEBlock);
        OneEBlock = nullptr;
    }
    return key;
}


void CheckAndWriteBackupKey(const std::string& filename, int flag)
{
    std::ifstream fileIn(filename);
    if(!fileIn.is_open()) 
    {
        std::string key;
        key = AES_GetEncryptKeyAndIV(flag);
        if(key != "")
        {   std::ofstream fileOut(filename);
            if (fileOut.is_open())
            {
                fileOut << key;
                fileOut.close();
                return;
            }
        }
        std::cerr << "Error: Unable to read key " <<  filename << " from firmware" << std::endl;
        return;
    }
    fileIn.close();
    return;
}

