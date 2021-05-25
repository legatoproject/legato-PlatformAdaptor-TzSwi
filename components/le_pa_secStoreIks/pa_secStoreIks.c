/**
 * @file pa_secStoreIks.c
 *
 * IKS implementation of @ref c_pa_secStore API.
 *
 * This Platform Adapter implementation of the Secure Storage stores data in the configTree.
 * The data is encrypted/decrypted using a key provided by Sierra Wireless IOT Key Store
 * solution.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"
#include "limit.h"
#include "interfaces.h"
#include "pa_secStore.h"
#include "iks_keyStore.h"

//--------------------------------------------------------------------------------------------------
/**
 * Config path to the secure storage content.
 */
//--------------------------------------------------------------------------------------------------
#define CFG_SECSTORE            "/secStore"

//--------------------------------------------------------------------------------------------------
/**
 * Key ID of key stored in IKS
 */
//--------------------------------------------------------------------------------------------------
#define IKS_KEY_ID             "SecStoreKey"

//--------------------------------------------------------------------------------------------------
/**
 * Max size of encrypted data.
 */
//--------------------------------------------------------------------------------------------------
#define MAX_ENCRYPTED_DATA_BYTES    4096

//--------------------------------------------------------------------------------------------------
/**
 * Max number of encrypted data buffers
 */
//--------------------------------------------------------------------------------------------------
#define MAX_ENCRYPTED_BUFFERS       1

//--------------------------------------------------------------------------------------------------
/**
 * Memory pool for encrypted data buffers
 */
//--------------------------------------------------------------------------------------------------
LE_MEM_DEFINE_STATIC_POOL(EncryptedBuffer, MAX_ENCRYPTED_BUFFERS, MAX_ENCRYPTED_DATA_BYTES);

//--------------------------------------------------------------------------------------------------
/**
 * Ecrypted Data Pool Handle
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t EncryptedBufferPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * IKS Key Ref used to encrypt/decrypt data
 */
//--------------------------------------------------------------------------------------------------
static iks_KeyRef_t KeyRef = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Get's SecStore KeyRef
 *
 * Tries to get KeyRef but if unable to do so, will try generating one.
 *
 * @return
 *      LE_OK if key is retrieved/generated successfully
 *      LE_FAULT if there was some other error.
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetKeyRef
(
    void
)
{
    if (iks_GetKey(IKS_KEY_ID, &KeyRef) != IKS_OK)
    {
        // Use keyPtr to pass back Key ID. The key itself is stored inside IoT KeyStore
        iks_result_t result = iks_CreateKeyByType(IKS_KEY_ID, IKS_KEY_TYPE_AES_GCM, 16, &KeyRef);
        if (IKS_DUPLICATE == result)
        {
            LE_WARN("Key already exists but getting it failed!");
            return LE_FAULT;
        }
        else if (IKS_OK != result)
        {
            LE_ERROR("Error creating key: %d", (int) result);
            return LE_FAULT;
        }

        result = iks_GenKeyValue(KeyRef, NULL, 0);
        if (IKS_OK != result)
        {
            LE_ERROR("Error generating key: %d", result);
            return LE_FAULT;
        }

        result = iks_SaveKey(KeyRef);
        if (IKS_OK != result)
        {
            LE_ERROR("Error saving key: %d", result);
            return LE_FAULT;
        }
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
static le_result_t EncryptData
(
    uint8_t* plainData,                 ///< [IN] Plain text.
    uint32_t plainDataSize,             ///< [IN] Size of plain text.
    uint8_t* encryptedData,             ///< [IN/OUT] Encrypted data.
    uint32_t* encryptedDataSizePtr      ///< [IN/OUT] Size of encrypted data.
)
{
    if ((KeyRef == NULL) && (GetKeyRef() != LE_OK))
    {
        LE_ERROR("Unable to get or generate key");
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
    iks_result_t result;

    // if data size allows, use "packet API" to reduce number of calls to iks_ library
    if (plainDataSize <= IKS_MAX_PACKET_SIZE)
    {
        result = iks_aesGcm_EncryptPacket(KeyRef,
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

        result = iks_CreateSession(KeyRef, &sessionRef);
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
            size_t currentSize = plainDataSize - (i * IKS_MAX_PACKET_SIZE);
            if (currentSize > IKS_MAX_PACKET_SIZE)
            {
                currentSize = IKS_MAX_PACKET_SIZE;
            }
            result = iks_aesGcm_Encrypt(sessionRef,
                                        plainData + (i * IKS_MAX_PACKET_SIZE),
                                        ciphertextPtr + (i * IKS_MAX_PACKET_SIZE),
                                        currentSize);
            if (IKS_OK != result)
            {
                LE_ERROR("Encrypt failed, %d", result);
                goto out;
            }
            i++;
        }
        while ((i * IKS_MAX_PACKET_SIZE) < plainDataSize);

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
static le_result_t DecryptData
(
    uint8_t* encryptedData,             ///< [IN] Encrypted data.
    uint32_t encryptedDataSize,         ///< [IN] Size of encrypted data.
    uint8_t* decryptedData,             ///< [IN/OUT] Decrypted data.
    uint32_t* decryptedDataSizePtr      ///< [IN/OUT] Size of decrypted data.
)
{
    if ((KeyRef == NULL) && (GetKeyRef() != LE_OK))
    {
        LE_ERROR("Unable to get or generate key");
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
    iks_result_t result;

    // if data size allows, use "packet API" to reduce number of calls to iks_ library
    if (decryptedSize <= IKS_MAX_PACKET_SIZE)
    {
        result = iks_aesGcm_DecryptPacket(KeyRef,
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
        result = iks_CreateSession(KeyRef, &sessionRef);
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
            size_t currentSize = decryptedSize - (i * IKS_MAX_PACKET_SIZE);
            if (currentSize > IKS_MAX_PACKET_SIZE)
            {
                currentSize = IKS_MAX_PACKET_SIZE;
            }
            result = iks_aesGcm_Decrypt(sessionRef,
                                        ciphertextPtr + (i * IKS_MAX_PACKET_SIZE),
                                        decryptedData + (i * IKS_MAX_PACKET_SIZE),
                                        currentSize);
            if (IKS_OK != result)
            {
                LE_ERROR("Decrypt failed, %d", result);
                goto out;
            }
            i++;
        }
        while ((i * IKS_MAX_PACKET_SIZE) < decryptedSize);

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
 * Writes the data in the buffer to the specified path in secure storage replacing any previously
 * written data at the same path.
 *
 * @return
 *      LE_OK if successful.
 *      LE_NO_MEMORY if there is not enough memory to store the data.
 *      LE_UNAVAILABLE if the secure storage is currently unavailable.
 *      LE_BAD_PARAMETER if the path cannot be written to because it is a directory or it would
 *                       result in an invalid path.
 *      LE_FAULT if there was some other error.
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_secStore_Write
(
    const char* pathPtr,            ///< [IN] Path to write to.
    const uint8_t* bufPtr,          ///< [IN] Buffer containing the data to write.
    size_t bufSize                  ///< [IN] Size of the buffer.
)
{
    // Encrypt the data
    uint8_t* encryptedBufPtr = le_mem_ForceAlloc(EncryptedBufferPool);
    LE_ASSERT(encryptedBufPtr != NULL);
    uint32_t encryptedBufSize = MAX_ENCRYPTED_DATA_BYTES;
    le_result_t result;

    // When we copy data from one system index to another, the buffered data
    // is already encrypted. We are just writing the data to another path.
    if (bufSize)
    {
        result = EncryptData((uint8_t*)bufPtr, bufSize, encryptedBufPtr, &encryptedBufSize);

        if (result != LE_OK)
        {
            LE_ERROR("Error encrypting data");
            goto exit;
        }
    }

    le_cfg_IteratorRef_t iteratorRef = le_cfg_CreateWriteTxn(CFG_SECSTORE);
    if (bufSize)
    {
        le_cfg_SetBinary(iteratorRef, pathPtr, encryptedBufPtr, encryptedBufSize);
    }
    else
    {
        if (bufSize != 0)
        {
            le_cfg_SetBinary(iteratorRef, pathPtr, bufPtr, bufSize);
        }
        else
        {
            // Special case of 0-size buffer, the data will be empty
            le_cfg_SetBinary(iteratorRef, pathPtr, (const uint8_t*)"", 0);
        }
    }
    le_cfg_CommitTxn(iteratorRef);

exit:
    le_mem_Release(encryptedBufPtr);
    return result;
}


//--------------------------------------------------------------------------------------------------
/**
 * Reads data from the specified path in secure storage.
 *
 * @return
 *      LE_OK if successful.
 *      LE_OVERFLOW if the buffer is too small to hold all the data.  No data will be written to the
 *                  buffer in this case.
 *      LE_NOT_FOUND if the path is empty.
 *      LE_UNAVAILABLE if the secure storage is currently unavailable.
 *      LE_FAULT if there was some other error.
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_secStore_Read
(
    const char* pathPtr,            ///< [IN] Path to read from.
    uint8_t* bufPtr,                ///< [OUT] Buffer to store the data in.
    size_t* bufSizePtr              ///< [IN/OUT] Size of buffer when this function is called.
                                    ///          Number of bytes read when this function returns.
)
{
    le_cfg_IteratorRef_t iteratorRef = le_cfg_CreateReadTxn(CFG_SECSTORE);
    uint8_t* encryptedDataPtr = NULL;
    uint32_t encryptedDataSize = MAX_ENCRYPTED_DATA_BYTES;
    uint8_t byte = 0;
    le_result_t result;

    if (!le_cfg_NodeExists(iteratorRef, pathPtr))
    {
        le_cfg_CancelTxn(iteratorRef);
        return LE_NOT_FOUND;
    }
    else if (*bufSizePtr == 0)
    {
        le_cfg_CancelTxn(iteratorRef);
        return LE_OK;
    }
    else
    {
        encryptedDataPtr = le_mem_ForceAlloc(EncryptedBufferPool);

        if (encryptedDataPtr == NULL)
        {
            LE_CRIT("Failed to get data buffer");
            le_cfg_CancelTxn(iteratorRef);
            return LE_FAULT;
        }

        result = le_cfg_GetBinary(iteratorRef,
                                  pathPtr,
                                  encryptedDataPtr,
                                  &encryptedDataSize,
                                  &byte,
                                  sizeof(byte));
        if (result != LE_OK)
        {
            LE_ERROR("Failed to get binary [%s].", pathPtr);
            goto exit;
        }

        // Manage case where the data is empty
        if (encryptedDataSize == 0)
        {
            memset(bufPtr, 0, *bufSizePtr);
            *bufSizePtr = 0;
        }
        else
        {
            result = DecryptData(encryptedDataPtr, encryptedDataSize, bufPtr, bufSizePtr);
            if (result != LE_OK)
            {
                LE_ERROR("Unable to decrypt: rc %s path [%s]", LE_RESULT_TXT(result), pathPtr);
            }
        }
    }

exit:
    le_cfg_CancelTxn(iteratorRef);
    le_mem_Release(encryptedDataPtr);
    return result;
}


//--------------------------------------------------------------------------------------------------
/**
 * Deletes the specified path and everything under it.
 *
 * @return
 *      LE_OK if successful.
 *      LE_NOT_FOUND if the path does not exist.
 *      LE_UNAVAILABLE if the secure storage is currently unavailable.
 *      LE_FAULT if there was an error.
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_secStore_Delete
(
    const char* pathPtr             ///< [IN] Path to delete.
)
{
    le_result_t result = LE_OK;
    le_cfg_IteratorRef_t iteratorRef = le_cfg_CreateWriteTxn(CFG_SECSTORE);

    if (!le_cfg_NodeExists(iteratorRef, pathPtr))
    {
        le_cfg_CancelTxn(iteratorRef);
        result = LE_NOT_FOUND;
    }
    else
    {
        le_cfg_DeleteNode(iteratorRef, pathPtr);
        le_cfg_CommitTxn(iteratorRef);
    }

    return result;
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets the size, in bytes, of the data at the specified path and everything under it.
 *
 * @return
 *      LE_OK if successful.
 *      LE_NOT_FOUND if the path does not exist.
 *      LE_UNAVAILABLE if the secure storage is currently unavailable.
 *      LE_FAULT if there was an error.
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_secStore_GetSize
(
    const char* pathPtr,            ///< [IN] Path.
    size_t* sizePtr                 ///< [OUT] Size in bytes of all items in the path.
)
{
    return LE_UNSUPPORTED;
}


//--------------------------------------------------------------------------------------------------
/**
 * Init this component
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    // Create memory pool to hold encrypted data contents
    EncryptedBufferPool = le_mem_InitStaticPool(EncryptedBuffer,
                                                MAX_ENCRYPTED_BUFFERS,
                                                MAX_ENCRYPTED_DATA_BYTES);
}
