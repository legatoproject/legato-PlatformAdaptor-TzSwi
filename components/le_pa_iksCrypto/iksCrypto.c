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
#if LE_CONFIG_TARGET_GILL
        // Workaround to reboot once when the first time
        // migrating keys from SFS to IKS fails.
        le_cfg_IteratorRef_t iteratorRef = le_cfg_CreateReadTxn("secStore:/");
        bool workaround_rebooted = le_cfg_GetBool(iteratorRef, "workaround_rebooted", false);
        le_cfg_CancelTxn(iteratorRef);
        if (!workaround_rebooted)
        {
            le_cfg_IteratorRef_t iteratorRef = le_cfg_CreateWriteTxn("secStore:/");
            le_cfg_SetBool(iteratorRef, "workaround_rebooted", true);
            le_cfg_CommitTxn(iteratorRef);
            LE_ERROR("Fatal error creating key and workaround to reboot");
            le_ulpm_Reboot();
            le_thread_Sleep(1);
        }
        else
        {
            LE_FATAL("Fatal error creating key");
        }
#endif
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
 * Retrieve a key from IoT Keystore (or from the locally cached copy) for the given Key ID.
 *
 * @return
 *      - true on success.
 *      - false on failure.
 */
//--------------------------------------------------------------------------------------------------
static bool GetKey
(
    uint8_t* keyIdPtr,          ///< [IN] Key ID.
    iks_KeyRef_t* keyRefPtr     ///< [OUT] Key reference.
)
{
    const char *keyId = (const char *) keyIdPtr;

#if LE_CONFIG_LINUX
    // If memory allows, try to re-use the last accessed key,
    // to skip the IKS key lookup.
    static char KeyIdCache[IKS_MAX_IDENTIFIER_SIZE] = {0};
    static iks_KeyRef_t KeyRefCache = NULL;

    if ((NULL != KeyRefCache) &&
        (0 == strncmp(KeyIdCache, keyId, sizeof(KeyIdCache))))
    {
        *keyRefPtr = KeyRefCache;
        return true;
    }
#endif

#if LE_CONFIG_TARGET_GILL
#define MAX_GETKEY_RETRIES 3

    int retry_counter = 0;
    iks_result_t iksRc = IKS_OK;
    do
    {
        iksRc = iks_GetKey(keyId, keyRefPtr);

        if (IKS_OK != iksRc)
        {
            LE_ERROR("Error getting key: %d", iksRc);
        }
        else
        {
            break;
        }
        retry_counter++;
        LE_DEBUG("iks_GetKey retries: %d", retry_counter);

    } while (retry_counter < MAX_GETKEY_RETRIES);

    if (retry_counter >= MAX_GETKEY_RETRIES)
    {
        LE_ERROR("iks_GetKey max retries: %d", retry_counter);
        return false;
    }

#else /* LE_CONFIG_TARGET_GILL */

    // Just get the actual key from the keystore.
    iks_result_t iksRc = iks_GetKey(keyId, keyRefPtr);

    if (IKS_OK != iksRc)
    {
        LE_ERROR("Error getting key: %d", iksRc);
        return false;
    }

#endif /* LE_CONFIG_TARGET_GILL */

#if LE_CONFIG_LINUX
    // Update the cached key
    if (LE_OK != le_utf8_Copy(KeyIdCache, keyId, sizeof(KeyIdCache), NULL))
    {
        LE_ERROR("Key ID cache overflow");
    }
    else
    {
        KeyRefCache = *keyRefPtr;
    }
#endif

    return true;
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

    if (!GetKey(keyIdPtr, &keyRef))
    {
        LE_ERROR("Error getting key '%s'", (char *) keyIdPtr);
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
    iks_Session_t sessionRef = NULL;

    // if data size allows, use "packet API" to reduce number of calls to iks_ library
    if (plainDataSize <= CHUNK_SIZE)
    {
        result = iks_aesGcm_EncryptPacket(keyRef,
                                          noncePtr,
                                          NULL,
                                          0,
                                          plainData,
                                          ciphertextPtr,
                                          plainDataSize,
                                          tagPtr,
                                          IKS_AES_GCM_TAG_SIZE);
        if (IKS_OK != result)
        {
            LE_ERROR("EncryptPacket failed, %d", result);
            goto out;
        }
    }
    else // data is too big to be processed as a single packet - use "streaming API"
    {
        int i = 0;

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
    }

out:
    if (NULL != sessionRef)
    {
        if (IKS_OK != iks_DeleteSession(sessionRef))
        {
            LE_ERROR("Error deleting session");
            return LE_FAULT;
        }
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

    if (!GetKey(keyIdPtr, &keyRef))
    {
        LE_ERROR("Error getting key '%s'", (char *) keyIdPtr);
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
    iks_Session_t sessionRef = NULL;

    // if data size allows, use "packet API" to reduce number of calls to iks_ library
    if (decryptedSize <= CHUNK_SIZE)
    {
        result = iks_aesGcm_DecryptPacket(keyRef,
                                          noncePtr,
                                          NULL,
                                          0,
                                          ciphertextPtr,
                                          decryptedData,
                                          decryptedSize,
                                          tagPtr,
                                          IKS_AES_GCM_TAG_SIZE);
        if (IKS_OK != result)
        {
            LE_ERROR("DecryptPacket failed, %d", result);
            goto out;
        }
    }
    else // data is too big to be processed as a single packet - use "streaming API"
    {
        int i = 0;
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
    }

out:
    if (NULL != sessionRef)
    {
        if (IKS_OK != iks_DeleteSession(sessionRef))
        {
            LE_ERROR("Error deleting session");
            return LE_FAULT;
        }
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
