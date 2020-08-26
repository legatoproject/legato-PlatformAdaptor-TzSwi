/** @file iksCrypto.c
 *
 * Provides a IoT Keystore based component that allows a process to generate new keys and use the
 * keys to encrypt and decrypt data.
 *
 * Copyright (C) Sierra Wireless Inc.
 */
//--------------------------------------------------------------------------------------------------

#include "legato.h"
#include "interfaces.h"
#include "iks_keyStore.h"
#include "iksCrypto.h"


//--------------------------------------------------------------------------------------------------
/**
 * Maximum size of data before we start chunking them into blocks.
 */
//--------------------------------------------------------------------------------------------------
#define CHUNK_SIZE 2048


/**-----------------------------------------------------------------------------------------------
 *
 * Generate a key from IoT Keystore
 *
 * @return
 *      - LE_OK
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t iksCrypto_GenerateKey
(
    uint8_t* keyPtr,                    ///< [IN/OUT] Key.
    uint32_t* keySizePtr                ///< [IN/OUT] Size of key.
)
{
    iks_KeyRef_t keyRef;
    iks_result_t result;
    uint64_t keyIdBinBuf;

    // Generate Key ID randomly, and encode it into string
    LE_ASSERT(IKS_OK == iks_rand_Get((uint8_t *) &keyIdBinBuf, sizeof(keyIdBinBuf)));

    snprintf((char *)keyPtr, *keySizePtr - 1, "%" PRIx64, keyIdBinBuf);

    const char *keyId = (const char *) keyPtr;

    // Use keyPtr to pass back Key ID. The key itself is stored inside IoT KeyStore
    result = iks_CreateKeyByType(keyId, IKS_KEY_TYPE_AES_GCM, 16, &keyRef);
    if (IKS_DUPLICATE == result)
    {
        LE_WARN("Key already exists! Nothing to do");
        return LE_OK; // TBD: return and handle duplicate?
    }
    else if (IKS_OK != result)
    {
        LE_ERROR("Error creating key: %d", (int) result);
        return LE_FAULT;
    }

    result = iks_GenKeyValue(keyRef, NULL, 0);
    if (IKS_OK != result)
    {
        LE_ERROR("Error generating key: %d", result);
        return LE_FAULT;
    }

    result = iks_SaveKey(keyRef);
    if (IKS_OK != result)
    {
        LE_ERROR("Error saving key: %d", result);
        return LE_FAULT;
    }

    return LE_OK;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Encrypt plain text data using key previously generated and kept in KeyStore
 *
 * @return
 *      - LE_OK
 *      - LE_OVERFLOW
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t iksCrypto_EncryptData
(
    uint8_t* keyIdPtr,                  ///< [IN] Key ID.
    uint32_t keyIdSize,                 ///< [IN] Size of key ID.
    uint8_t* plainData,                 ///< [IN] Plain text.
    uint32_t plainDataSize,             ///< [IN] Size of plain text.
    uint8_t* encryptedData,             ///< [IN/OUT] Encrypted data.
    uint32_t* encryptedDataSizePtr      ///< [IN/OUT] Size of encrypted data.
)
{
    iks_KeyRef_t keyRef;
    iks_result_t result;

    // Get the actual key from the keystore.
    const char *keyId = (const char *) keyIdPtr;
    result = iks_GetKey(keyId, &keyRef);
    if (IKS_OK != result)
    {
        LE_ERROR("Error getting key: %d", result);
        return LE_FAULT;
    }

    // Calculate the encrypted data size, and check whether it fits in the buffer
    size_t encryptedSize = IKS_AES_GCM_NONCE_SIZE + IKS_AES_GCM_TAG_SIZE + plainDataSize;
    if (encryptedSize > *encryptedDataSizePtr)
    {
        LE_ERROR("insufficient ciphertext buffer: %" PRIuS " < %u",
                 encryptedSize, *encryptedDataSizePtr);
        return LE_OVERFLOW;
    }
    *encryptedDataSizePtr = encryptedSize;

    uint8_t* noncePtr = encryptedData;
    uint8_t* tagPtr = noncePtr + IKS_AES_GCM_NONCE_SIZE;
    uint8_t* ciphertextPtr = tagPtr + IKS_AES_GCM_TAG_SIZE;

    // Create a session.
    iks_Session_t sessionRef;

    result = iks_CreateSession(keyRef, &sessionRef);
    if (IKS_OK != result)
    {
        LE_ERROR("Error creating session: %d", result);
        return LE_FAULT;
    }

    result = iks_aesGcm_StartEncrypt(sessionRef, noncePtr);
    if (IKS_OK != result)
    {
        LE_ERROR("StartEncrypt failed, %d", result);
        goto out;
    }

    // Splitting buffer into chunks (if necessary)
    int i = 0;
    do
    {
        size_t currentSize = plainDataSize - (i * CHUNK_SIZE);
        if (currentSize > CHUNK_SIZE)
        {
            currentSize = CHUNK_SIZE;
        }
        result = iks_aesGcm_Encrypt(sessionRef,
                                    plainData + (i * CHUNK_SIZE),
                                    ciphertextPtr + (i * CHUNK_SIZE),
                                    currentSize);
        if (IKS_OK != result)
        {
            LE_ERROR("Encrypt failed, %d", result);
            goto out;
        }
        i++;
    }
    while ((i * CHUNK_SIZE) < plainDataSize);

    // Finalize encryption
    result = iks_aesGcm_DoneEncrypt(sessionRef, tagPtr, IKS_AES_GCM_TAG_SIZE);
    if (IKS_OK != result)
    {
        LE_ERROR("DoneEncrypt failed, %d", result);
        goto out;
    }

out:
    if (IKS_OK != iks_DeleteSession(sessionRef))
    {
        LE_ERROR("Error deleting session");
        return LE_FAULT;
    }

    return (IKS_OVERFLOW == result) ? LE_OVERFLOW :
                                      (IKS_OK == result) ? LE_OK : LE_FAULT;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Decrypt encrypted data using key previously generated and kept in KeyStore.
 *
 * @return
 *      - LE_OK
 *      - LE_OVERFLOW
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t iksCrypto_DecryptData
(
    uint8_t* keyIdPtr,                  ///< [IN] Key ID.
    uint32_t keyIdSize,                 ///< [IN] Size of key ID.
    uint8_t* encryptedData,             ///< [IN] Encrypted data.
    uint32_t encryptedDataSize,         ///< [IN] Size of encrypted data.
    uint8_t* decryptedData,             ///< [IN/OUT] Decrypted data.
    uint32_t* decryptedDataSizePtr      ///< [IN/OUT] Size of decrypted data.
)
{
    iks_KeyRef_t keyRef;
    iks_result_t result;

    // Get the actual key from the keystore.
    const char *keyId = (const char *) keyIdPtr;
    result = iks_GetKey(keyId, &keyRef);
    if (IKS_OK != result)
    {
        LE_ERROR("Error getting key: %d", result);
        return LE_FAULT;
    }

    // Sanity-check encrypted buffer size
    LE_ASSERT(encryptedDataSize >= IKS_AES_GCM_NONCE_SIZE + IKS_AES_GCM_TAG_SIZE);

    // Calculate the decrypted data size, and check whether it fits in the buffer
    size_t decryptedSize = encryptedDataSize - IKS_AES_GCM_NONCE_SIZE - IKS_AES_GCM_TAG_SIZE;
    if (decryptedSize > *decryptedDataSizePtr)
    {
        LE_ERROR("insufficient plaintext buffer: %" PRIuS " < %u",
                 decryptedSize, *decryptedDataSizePtr);
        return LE_OVERFLOW;
    }

    *decryptedDataSizePtr = decryptedSize;
    uint8_t* noncePtr = encryptedData;
    uint8_t* tagPtr = noncePtr + IKS_AES_GCM_NONCE_SIZE;
    uint8_t* ciphertextPtr = tagPtr + IKS_AES_GCM_TAG_SIZE;

    // Create a session.
    iks_Session_t sessionRef;

    result = iks_CreateSession(keyRef, &sessionRef);
    if (IKS_OK != result)
    {
        LE_ERROR("Error creating session: %d", result);
        return LE_FAULT;
    }

    result = iks_aesGcm_StartDecrypt(sessionRef, noncePtr);
    if (IKS_OK != result)
    {
        LE_ERROR("StartDecrypt failed, %d", result);
        goto out;
    }

    // Splitting buffer into chunks (if necessary)
    int i = 0;
    do
    {
        size_t currentSize = decryptedSize - (i * CHUNK_SIZE);
        if (currentSize > CHUNK_SIZE)
        {
            currentSize = CHUNK_SIZE;
        }
        result = iks_aesGcm_Decrypt(sessionRef,
                                    ciphertextPtr + (i * CHUNK_SIZE),
                                    decryptedData + (i * CHUNK_SIZE),
                                    currentSize);
        if (IKS_OK != result)
        {
            LE_ERROR("Decrypt failed, %d", result);
            goto out;
        }
        i++;
    }
    while ((i * CHUNK_SIZE) < decryptedSize);

    // Finalize decryption
    result = iks_aesGcm_DoneDecrypt(sessionRef, tagPtr, IKS_AES_GCM_TAG_SIZE);
    if (IKS_OK != result)
    {
        LE_ERROR("DoneDecrypt failed, %d", result);
        goto out;
    }

out:
    if (IKS_OK != iks_DeleteSession(sessionRef))
    {
        LE_ERROR("Error deleting session");
        return LE_FAULT;
    }

    return (IKS_OVERFLOW == result) ? LE_OVERFLOW :
                                      (IKS_OK == result) ? LE_OK : LE_FAULT;
}


//--------------------------------------------------------------------------------------------------
/**
 * Component initializer.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
}