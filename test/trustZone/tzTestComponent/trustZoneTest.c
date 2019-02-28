#include "legato.h"
#include "trustZone.h"

// Global variables used to store info shared between multiple test cases
static uint8_t Key[KM_MAX_KEY_SIZE];
static uint32_t KeySize = KM_MAX_KEY_SIZE;
static uint8_t EncryptedData[1024];
static uint32_t EncryptedDataSize = 1024;
static char PlainText[] = "Quick brown fox jumps over the lazy dog";

#define TEST_MAX_DATA_SIZE 12276

void tz_TC1()
{
    LE_TEST_INFO("== Running basic use case: generate key, encrypt and decrypt ==");

    le_result_t result = tz_GenerateKey(Key, &KeySize);
    LE_TEST_ASSERT(result == LE_OK, "Generating key.");
    LE_TEST_INFO("Key size: %d", KeySize);

    // Encrypting text
    uint8_t* plainData = (uint8_t *)PlainText;;
    uint32_t plainDataSize = sizeof(PlainText);

    result = tz_EncryptData(Key, KeySize, plainData, plainDataSize, EncryptedData, &EncryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Encrypting text.");
    LE_TEST_INFO("Encrypted data size: %d", EncryptedDataSize);

    uint8_t decryptedData[1024];
    uint32_t decryptedDataSize = sizeof(decryptedData);

    // Decrypting text
    result = tz_DecryptData(Key, KeySize, EncryptedData, EncryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Decrypting text.");
    LE_TEST_INFO("Decrypted text [%s], size [%d]", decryptedData, decryptedDataSize);
    LE_TEST_OK(plainDataSize == decryptedDataSize, "Check decrypted data size.");
    LE_TEST_OK(memcmp(plainData, decryptedData, decryptedDataSize) == 0, "Check decrypted data.");

    LE_TEST_INFO("===================================");
}


void tz_TC2()
{
    LE_TEST_INFO("== Key generation tests == ");

    // Various key generation parameters

    // Key buffer is not sufficient but keysize is
    uint8_t key[32];
    uint32_t keySize = sizeof(key) * 2;
    le_result_t result = tz_GenerateKey(key, &keySize);
    LE_TEST_OK(result == LE_OK, "Generating key [key buffer not sufficient but key size is].");

    // Key size 0 - BUG: Unable to handle kernel NULL pointer dereference at virtual address 00000000 [Crashes process]
    /*
    keySize = 0;
    result = tz_GenerateKey(key, &keySize);
    LE_TEST_ASSERT(result == LE_FAULT, "Generating key [key size 0].");
    */

    // Key buffer is sufficient but keysize is not
    uint8_t key1[KM_MAX_KEY_SIZE];
    keySize = sizeof(key1)/2;
    result = tz_GenerateKey(key, &keySize);
    LE_TEST_OK(result == LE_FAULT, "Generating key [key buffer sufficient but not key size].");

    LE_TEST_INFO("===================================");
}

void tz_TC3()
{
    // When buffer exceeds the 8K limit, the tz device will error. Ensure that the trustzone component
    // manages this use case properly even if data is < 8K.
    LE_TEST_INFO("== Testing with buffers > 8K limit but data is < 8K == ");

    uint8_t key[KM_MAX_KEY_SIZE];
    uint32_t keySize = sizeof(key);
    le_result_t result = tz_GenerateKey(key, &keySize);
    LE_TEST_ASSERT(result == LE_OK, "Generating key.");
    LE_TEST_INFO("Key size: %d", keySize);

    // Encrypting text
    uint8_t* plainData = (uint8_t *)PlainText;;
    uint32_t plainDataSize = sizeof(PlainText);

    static uint8_t encryptedData[TEST_MAX_DATA_SIZE];
    static uint32_t encryptedDataSize = sizeof(encryptedData);

    result = tz_EncryptData(key, keySize, plainData, plainDataSize, encryptedData, &encryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Encrypting text.");
    LE_TEST_INFO("Encrypted data size: %d", encryptedDataSize);

    uint8_t decryptedData[TEST_MAX_DATA_SIZE];
    uint32_t decryptedDataSize = sizeof(decryptedData);

    // Decrypting text
    result = tz_DecryptData(key, keySize, encryptedData, encryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Decrypting text.");
    LE_TEST_INFO("Decrypted text [%s], size [%d]", decryptedData, decryptedDataSize);
    LE_TEST_OK(plainDataSize == decryptedDataSize, "Check decrypted data size.");
    LE_TEST_OK(memcmp(plainData, decryptedData, decryptedDataSize) == 0, "Check decrypted data.");
}


void tz_TC4()
{
    // This tests the chunking behaviour if data exceeds 8K.
    LE_TEST_INFO("== Testing with buffers > 8K limit and data is > 8K == ");

    uint8_t key[KM_MAX_KEY_SIZE];
    uint32_t keySize = sizeof(key);
    le_result_t result = tz_GenerateKey(key, &keySize);
    LE_TEST_ASSERT(result == LE_OK, "Generating key.");
    LE_TEST_INFO("Key size: %d", keySize);

    char str[TEST_MAX_DATA_SIZE];
    FILE* fp;
    fp = fopen("/usr/LongPlainText", "r");
    LE_TEST_ASSERT(fp != NULL, "Reading file.");

    while (fscanf(fp, "%s", str) != EOF)
        LE_DEBUG("str: %s", str);
    fclose(fp);

    // Encrypting text
    uint8_t* plainData = (uint8_t *)str;
    uint32_t plainDataSize = strlen(str);

    static uint8_t encryptedData[TEST_MAX_DATA_SIZE];
    static uint32_t encryptedDataSize = sizeof(encryptedData);

    result = tz_EncryptData(key, keySize, plainData, plainDataSize, encryptedData, &encryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Encrypting text.");
    LE_TEST_INFO("Encrypted data size: %d", encryptedDataSize);

    uint8_t decryptedData[TEST_MAX_DATA_SIZE];
    uint32_t decryptedDataSize = sizeof(decryptedData);

    // Decrypting text
    result = tz_DecryptData(key, keySize, encryptedData, encryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Decrypting text.");
    LE_TEST_INFO("Decrypted text [%s], size [%d]", decryptedData, decryptedDataSize);
    LE_TEST_OK(plainDataSize == decryptedDataSize, "Check decrypted data size.");
    LE_TEST_OK(memcmp(plainData, decryptedData, decryptedDataSize) == 0, "Check decrypted data.");
}

void tz_TC5()
{
    LE_TEST_INFO("== Decryption tests ==");
    uint8_t decryptedData[1024];
    uint32_t decryptedDataSize = sizeof(decryptedData);

    // Try various decryption parameters

    // Key size of 0 - BUG: Unable to handle kernel NULL pointer dereference at virtual address 00000000 [Crashes process]
    /*
    le_result_t result = tz_DecryptData(Key, 0, EncryptedData, EncryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_FAULT, "Decrypting text [key size 0].");
    */

    // Key size < actual key size
    le_result_t result = tz_DecryptData(Key, KeySize - 1, EncryptedData, EncryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_OK(result == LE_FAULT, "Decrypting text [key size < actual key size].");

    // Key size > actual key size
    result = tz_DecryptData(Key, KeySize + 1, EncryptedData, EncryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_OK(result == LE_FAULT, "Decrypting text [key size > actual key size].");

    // Encrypted data size 0 - BUG: Unable to handle kernel NULL pointer dereference at virtual address 00000000 [Crashes process]
    /*
    result = tz_DecryptData(Key, sizeof(Key), EncryptedData, 0, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_FAULT, "Decrypting text [Encrypted data size 0].");
    */

    // Encrypted data size < actual encrypted data size
    result = tz_DecryptData(Key, KeySize, EncryptedData, EncryptedDataSize - 1, decryptedData, &decryptedDataSize);
    LE_TEST_OK(result == LE_FAULT, "Decrypting text [Encrypted data size < Actual encrypted data size].");

    // Encrypted data size > actual encrypted data size
    result = tz_DecryptData(Key, KeySize, EncryptedData, EncryptedDataSize + 1, decryptedData, &decryptedDataSize);
    LE_TEST_OK(result == LE_FAULT, "Decrypting text [Encrypted data size > Actual encrypted data size].");

    // Decrypted data size 0 - BUG: Unable to handle kernel NULL pointer dereference at virtual address 00000000 [Crashes process]
    /*
    decryptedDataSize = 0;
    result = tz_DecryptData(Key, sizeof(Key), EncryptedData, sizeof(EncryptedData) + 1, decryptedData, &decryptedDataSize);
    LE_TEST_ASSERT(result == LE_FAULT, "Decrypting text [decrypt size 0].");
    */

    // Proper decryption
    uint8_t* plainData = (uint8_t *)PlainText;
    uint32_t plainDataSize = sizeof(PlainText);;

    result = tz_DecryptData(Key, KeySize, EncryptedData, EncryptedDataSize, decryptedData, &decryptedDataSize);
    LE_TEST_OK(result == LE_OK, "Decrypting text.");
    LE_TEST_INFO("Decrypted text [%s], size [%d]", decryptedData, decryptedDataSize);
    LE_TEST_OK(plainDataSize == decryptedDataSize, "Check decrypted data size.");
    LE_TEST_OK(memcmp(plainData, decryptedData, decryptedDataSize) == 0, "Check decrypted data.");

    LE_TEST_INFO("===================================");
}


void tz_TC6()
{
    LE_TEST_INFO("== Overflow tests ==");

    // Encrypting text
    uint8_t* plainData = (uint8_t *)PlainText;;
    uint32_t plainDataSize = sizeof(PlainText);

    // First test is to use a buffer that is smaller than our plain data
    uint8_t smallEncryptedData[plainDataSize-1];
    uint32_t smallEncryptedDataSize = sizeof(smallEncryptedData);

    le_result_t result = tz_EncryptData(Key, KeySize, plainData, plainDataSize, smallEncryptedData, &smallEncryptedDataSize);
    LE_TEST_ASSERT(result == LE_OVERFLOW, "Encrypting text into small buffer.");

    uint8_t encryptedData[1024];
    uint32_t encryptedDataSize = sizeof(encryptedData);

    result = tz_EncryptData(Key, KeySize, plainData, plainDataSize, encryptedData, &encryptedDataSize);
    LE_TEST_ASSERT(result == LE_OK, "Encrypting text.");

    // Decrypt text into a smaller buffer
    uint8_t smallDecryptedData[plainDataSize-1];
    uint32_t smallDecryptedDataSize = sizeof(smallDecryptedData);
    result = tz_DecryptData(Key, KeySize, encryptedData, encryptedDataSize, smallDecryptedData, &smallDecryptedDataSize);
    LE_TEST_ASSERT(result == LE_OVERFLOW, "Decrypting text into small buffer.");
}


COMPONENT_INIT
{
    tz_TC1();
    tz_TC2();
    tz_TC3();
    tz_TC4();
    tz_TC5();
    tz_TC6();
    LE_TEST_EXIT;
}