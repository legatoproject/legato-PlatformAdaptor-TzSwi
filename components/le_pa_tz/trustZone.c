//--------------------------------------------------------------------------------------------------
/** @file trustZone.c
 *
 * Provides a TrustZone component that allows a process to generate new keys and use the keys to
 * encrypt and decrypt data.
 *
 * Copyright (C) Sierra Wireless Inc.
 */
//--------------------------------------------------------------------------------------------------

#include "legato.h"
#include "interfaces.h"
#include "trustZone.h"

#define TZDEV_IOCTL_MAGIC           0x9B

#define TZDEV_IOCTL_KEYGEN_REQ      _IOWR(TZDEV_IOCTL_MAGIC, 0x16, TzOpReq_t)
#define TZDEV_IOCTL_SEAL_REQ        _IOWR(TZDEV_IOCTL_MAGIC, 0x17, TzOpReq_t)
#define TZDEV_IOCTL_UNSEAL_REQ      _IOWR(TZDEV_IOCTL_MAGIC, 0x18, TzOpReq_t)

//--------------------------------------------------------------------------------------------------
/**
 * Trust zone device.
 */
//--------------------------------------------------------------------------------------------------
#define SIERRA_TZDEV_DEV_PATH       "/dev/tzdev"

//--------------------------------------------------------------------------------------------------
/**
 * Maximum size of data before we start chunking them into blocks.
 */
//--------------------------------------------------------------------------------------------------
#define MAX_DATA_SIZE               2048

//--------------------------------------------------------------------------------------------------
/**
 * Arbitrary size known to be greater than actual encryption overhead
 */
//--------------------------------------------------------------------------------------------------
#define TZ_OVERHEAD                 128

//--------------------------------------------------------------------------------------------------
/**
 * Trust zone device command and structure definition, must keep adapted to kernel code.
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t* encKey;
    uint32_t encKeyLen;
    uint8_t* plainData;
    uint32_t plainDataLen;
    uint8_t* encryptedData;
    uint32_t encryptedDataLen;
}
TzOpReq_t;

//--------------------------------------------------------------------------------------------------
/**
 * Plain data buffer memory pool
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t PlainDataPoolRef = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Encrypted data buffer memory pool
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t EncryptedDataPoolRef = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Open the device and create ioctl
 */
//--------------------------------------------------------------------------------------------------
static int TzIoctl
(
    int cmd,                        ///< [IN] Command (Gen key, encrypt or decrypt).
    unsigned long* data             ///< [IN] Structure containing the necessary data for the cmd.
)
{
    int fd;
    int ioctlRet = 0;

    fd = open(SIERRA_TZDEV_DEV_PATH, O_SYNC);
    if (fd < 0)
    {
        LE_ERROR("open %s failed", SIERRA_TZDEV_DEV_PATH);
        return -1;
    }

    ioctlRet = ioctl(fd, cmd, data);
    if (0 > ioctlRet)
    {
      LE_ERROR("ioctl %s failed, ret=%d", SIERRA_TZDEV_DEV_PATH, ioctlRet);
    }

    (void)close(fd);

    return ioctlRet;
}


//--------------------------------------------------------------------------------------------------
/**
 * Send the request to the TrustZone device
 */
//--------------------------------------------------------------------------------------------------
static bool SendTzRequest
(
    uint32_t cmdId,                ///< [IN] Command.
    uint8_t* key,                  ///< [IN/OUT] Key.
    uint32_t* keyLen,              ///< [IN/OUT] Size of key.
    uint8_t* plainData,            ///< [IN/OUT] Plain text.
    uint32_t* plainDataLen,        ///< [IN/OUT] Size of plain text.
    uint8_t* encryptedData,        ///< [IN/OUT] Encrypted buffer.
    uint32_t* encryptedDataLen     ///< [IN/OUT] Size of encrypted buffer.
)
{
    TzOpReq_t tzReq;
    int ret;

    tzReq.encKey = key;
    tzReq.encKeyLen = *keyLen;


    if((TZDEV_IOCTL_SEAL_REQ == cmdId) || (TZDEV_IOCTL_UNSEAL_REQ == cmdId))
    {
        tzReq.plainData = plainData;
        tzReq.plainDataLen = *plainDataLen;
        tzReq.encryptedData = encryptedData;
        tzReq.encryptedDataLen = *encryptedDataLen;
    }
    else if(TZDEV_IOCTL_KEYGEN_REQ == cmdId)
    {
        tzReq.plainDataLen = 0;
        tzReq.encryptedDataLen = 0;
    }

    ret = TzIoctl(cmdId, (unsigned long *)&tzReq);
    if(ret < 0)
    {
        LE_ERROR("TzIoctl ret=%d", ret);
        return false;
    }

    if(TZDEV_IOCTL_KEYGEN_REQ == cmdId)
    {
        *keyLen = tzReq.encKeyLen;
    }
    else if(TZDEV_IOCTL_SEAL_REQ == cmdId)
    {
        *encryptedDataLen = tzReq.encryptedDataLen;
    }
    else if(TZDEV_IOCTL_UNSEAL_REQ == cmdId)
    {
        *plainDataLen = tzReq.plainDataLen;
    }

    return true;
}

/**-----------------------------------------------------------------------------------------------
 *
 * Generate a key from TrustZone.
 *
 * @return
 *      - LE_OK
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t tz_GenerateKey
(
    uint8_t* keyPtr,                    ///< [IN/OUT] Key.
    uint32_t* keySizePtr                ///< [IN/OUT] Size of key.
)
{
    if ((keyPtr == NULL) || (keySizePtr == NULL) || (*keySizePtr == 0))
    {
        LE_ERROR("Invalid parameter: %s",((!keyPtr)||(!keySizePtr))?
                 "keyPtr or keySizePtr is NULL":"keySize is 0");
        return LE_FAULT;
    }
    if (!SendTzRequest(TZDEV_IOCTL_KEYGEN_REQ, keyPtr, keySizePtr, NULL, NULL, NULL, NULL)
        || (*keySizePtr > KM_MAX_KEY_SIZE))
    {
        LE_ERROR("Error generating key.");
        return LE_FAULT;
    }

    return LE_OK;
}

/**-----------------------------------------------------------------------------------------------
 *
 * Used to determine exactly how many encrypted bytes are produced from plaintext of MAX_DATA_SIZE.
 *
 * @return
 *      - Size of the encrypted buffer produced from MAX_DATA_SIZE plaintext
 *      - 0 on failure
 */
//--------------------------------------------------------------------------------------------------
static uint32_t GetMaxEncryptedSize
(
    uint8_t* keyPtr,                    ///< [IN] Key.
    uint32_t keySize                    ///< [IN] Size of key.
)
{
    /*
     * Maximum encrypted buffer required to store MAX_DATA_SIZE when encrypted.
     * The size is deterministic and does not matter on the content of the buffer.
     * This is calculated by encrypting any buffer of MAX_DATA_SIZE and checking how many bytes
     * tz uses. Zero means it's not calculated yet.
     */
    static uint32_t     maxEncryptedSize = 0;
    static bool         initDone = false;

    // Initialize memory pools and dry-run encryption operation.
    if (!initDone)
    {
        if (PlainDataPoolRef == NULL)
        {
            PlainDataPoolRef = le_mem_CreatePool("PlainDataBuffer", MAX_DATA_SIZE);
        }
        if (EncryptedDataPoolRef == NULL)
        {
            EncryptedDataPoolRef = le_mem_CreatePool("EncryptedDataBuffer",
                                                     MAX_DATA_SIZE + TZ_OVERHEAD);
        }
        uint8_t *plainDataPtr = le_mem_ForceAlloc(PlainDataPoolRef);
        memset (plainDataPtr, 0, MAX_DATA_SIZE);
        uint32_t plainDataSize = MAX_DATA_SIZE;
        uint8_t *encryptedDataPtr = le_mem_ForceAlloc(EncryptedDataPoolRef);
        uint32_t encryptedDataSize = MAX_DATA_SIZE + TZ_OVERHEAD;

        if (!SendTzRequest(TZDEV_IOCTL_SEAL_REQ, keyPtr, &keySize,
            plainDataPtr, &plainDataSize, encryptedDataPtr, &encryptedDataSize))
        {
            LE_ERROR("Error encrypting max buffer.");
        }
        else
        {
            maxEncryptedSize = encryptedDataSize;
            LE_INFO("Calculated maxEncryptedSize = %d", maxEncryptedSize);
            initDone = true;
        }

        le_mem_Release(plainDataPtr);
        le_mem_Release(encryptedDataPtr);
    }

    return maxEncryptedSize;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Encrypt plain text data using key generated by TrustZone.
 *
 * @return
 *      - LE_OK
 *      - LE_OVERFLOW
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t tz_EncryptData
(
    uint8_t* keyPtr,                    ///< [IN] Key.
    uint32_t keySize,                   ///< [IN] Size of key.
    uint8_t* plainData,                 ///< [IN] Plain text.
    uint32_t plainDataSize,             ///< [IN] Size of plain text.
    uint8_t* encryptedData,             ///< [IN/OUT] Encrypted data.
    uint32_t* encryptedDataSizePtr      ///< [IN/OUT] Size of encrypted data.
)
{
    if ((keySize > KM_MAX_KEY_SIZE) || (keySize == 0))
    {
        LE_ERROR("Invalid key");
        return LE_FAULT;
    }

    uint32_t maxEncryptedSize = GetMaxEncryptedSize(keyPtr, keySize);
    if (0 == maxEncryptedSize)
    {
        LE_ERROR("Error calculating max encrypted size");
        return LE_FAULT;
    }

    LE_DEBUG("Encrypting data: size %u to buffer size %u",
             plainDataSize, *encryptedDataSizePtr);
    size_t bytesProcessed = 0;
    size_t bytesEncrypted = 0;
    uint8_t *encryptedDataPtr = le_mem_ForceAlloc(EncryptedDataPoolRef);
    le_result_t result = LE_OK;

    while (bytesProcessed < plainDataSize)
    {
        size_t pDataSize = plainDataSize - bytesProcessed;

        if (pDataSize > MAX_DATA_SIZE)
        {
            pDataSize = MAX_DATA_SIZE;
        }

        size_t eDataSize = maxEncryptedSize;

        if (!SendTzRequest(TZDEV_IOCTL_SEAL_REQ, keyPtr, &keySize,
            &(plainData[bytesProcessed]), &pDataSize, encryptedDataPtr, &eDataSize))
        {
            LE_ERROR("Error encrypting string.");
            result = LE_FAULT;
            break;
        }

        if (*encryptedDataSizePtr < (bytesEncrypted + eDataSize))
        {
            LE_ERROR("Output buffer overflow!");
            result = LE_OVERFLOW;
            break;
        }
        else
        {
            memcpy(&encryptedData[bytesEncrypted], encryptedDataPtr, eDataSize);
        }

        bytesProcessed += pDataSize;
        bytesEncrypted += eDataSize;
    }

    *encryptedDataSizePtr = bytesEncrypted;
    le_mem_Release(encryptedDataPtr);
    return result;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Decrypt encrypted data using key generated by TrustZone.
 *
 * @return
 *      - LE_OK
 *      - LE_OVERFLOW
 *      - LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t tz_DecryptData
(
    uint8_t* keyPtr,                    ///< [IN] Key.
    uint32_t keySize,                   ///< [IN] Size of key.
    uint8_t* encryptedData,             ///< [IN] Encrypted data.
    uint32_t encryptedDataSize,         ///< [IN] Size of encrypted data.
    uint8_t* decryptedData,             ///< [IN/OUT] Decrypted data.
    uint32_t* decryptedDataSizePtr      ///< [IN/OUT] Size of decrypted data.
)
{
    if ((keySize > KM_MAX_KEY_SIZE) || (keySize == 0))
    {
        LE_ERROR("Invalid key");
        return LE_FAULT;
    }

    uint32_t maxEncryptedSize = GetMaxEncryptedSize(keyPtr, keySize);
    if (0 == maxEncryptedSize)
    {
        LE_ERROR("Error calculating max encrypted size");
        return LE_FAULT;
    }

    LE_DEBUG("Decrypting data: size %u to buffer size %u",
             encryptedDataSize, *decryptedDataSizePtr);
    size_t bytesProcessed = 0;
    size_t bytesDecrypted = 0;
    uint8_t *plainDataPtr = le_mem_ForceAlloc(PlainDataPoolRef);
    le_result_t result = LE_OK;

    while (bytesProcessed < encryptedDataSize)
    {
        size_t eDataSize = encryptedDataSize - bytesProcessed;

        if (eDataSize > maxEncryptedSize)
        {
            eDataSize = maxEncryptedSize;
        }

        size_t dDataSize = MAX_DATA_SIZE;

        if (!SendTzRequest(TZDEV_IOCTL_UNSEAL_REQ, keyPtr, &keySize,
            plainDataPtr, &dDataSize, &(encryptedData[bytesProcessed]), &eDataSize))
        {
            LE_ERROR("Error decrypting string.");
            result = LE_FAULT;
            break;
        }

        if (*decryptedDataSizePtr < (bytesDecrypted + dDataSize))
        {
            LE_ERROR("Output buffer overflow!");
            result = LE_OVERFLOW;
            break;
        }
        else
        {
            memcpy(&decryptedData[bytesDecrypted], plainDataPtr, dDataSize);
        }

        bytesProcessed += eDataSize; // Should be the same as get encrypted size.
        bytesDecrypted += dDataSize;
    }

    *decryptedDataSizePtr = bytesDecrypted;
    le_mem_Release(plainDataPtr);
    return result;
}


COMPONENT_INIT
{
}