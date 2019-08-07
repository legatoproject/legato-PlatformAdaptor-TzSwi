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
    uint8_t             plainData[MAX_DATA_SIZE] = {0};
    uint32_t            plainDataSize = MAX_DATA_SIZE;
    int                 overhead = 128; // Arbritrary size known to be greater than actual overhead
    uint8_t             buf[MAX_DATA_SIZE + overhead];
    uint32_t            bufSize = sizeof(buf);
    /*
     * Maximum encrypted buffer required to store MAX_DATA_SIZE when encrypted.
     * The size is deterministic and does not matter on the content of the buffer.
     * This is calculated by encrypting any buffer of MAX_DATA_SIZE and checking how many bytes
     * tz uses. Zero means it's not calculated yet.
     */
    static uint32_t     maxEncryptedSize = 0;

    // Dry-run encryption operation, performed only once.
    if (0 == maxEncryptedSize)
    {
        if (!SendTzRequest(TZDEV_IOCTL_SEAL_REQ, keyPtr, &keySize,
            plainData, &plainDataSize, buf, &bufSize))
        {
            LE_ERROR("Error encrypting max buffer.");
        }
        else
        {
            maxEncryptedSize = bufSize;
            LE_INFO("Calculated maxEncryptedSize = %d", maxEncryptedSize);
        }
    }

    return maxEncryptedSize;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Encrypt plain text data using key generated by TrustZone.
 *
 * @return
 *      - LE_OK
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

    LE_DEBUG("Encrypting data, size [%d]", plainDataSize);
    size_t bytesProcessed = 0;
    size_t bytesEncrypted = 0;
    do
    {
        size_t pDataSize = plainDataSize - bytesProcessed;

        if (pDataSize > MAX_DATA_SIZE)
        {
            pDataSize = MAX_DATA_SIZE;
        }

        size_t eDataSize = *encryptedDataSizePtr - bytesEncrypted;

        if (eDataSize > maxEncryptedSize)
        {

            eDataSize = maxEncryptedSize;
        }

        if (!SendTzRequest(TZDEV_IOCTL_SEAL_REQ, keyPtr, &keySize,
            &(plainData[bytesProcessed]), &pDataSize, &(encryptedData[bytesEncrypted]), &eDataSize))
        {
            LE_ERROR("Error encrypting string.");
            return LE_FAULT;
        }

        bytesProcessed += pDataSize;
        bytesEncrypted += eDataSize;

        if (bytesEncrypted > *encryptedDataSizePtr)
        {
            return LE_OVERFLOW;
        }
    }
    while (bytesProcessed < plainDataSize);

    *encryptedDataSizePtr = bytesEncrypted;

    return LE_OK;
}


/**-----------------------------------------------------------------------------------------------
 *
 * Decrypt encrypted data using key generated by TrustZone.
 *
 * @return
 *      - LE_OK
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

    size_t bytesProcessed = 0;
    size_t bytesDecrypted = 0;
    do
    {
        size_t eDataSize = encryptedDataSize - bytesProcessed;

        if (eDataSize > maxEncryptedSize)
        {

            eDataSize = maxEncryptedSize;
        }

        size_t dDataSize = *decryptedDataSizePtr - bytesDecrypted;

        if (dDataSize > MAX_DATA_SIZE)
        {
            dDataSize = MAX_DATA_SIZE;
        }

        if (!SendTzRequest(TZDEV_IOCTL_UNSEAL_REQ, keyPtr, &keySize,
            &(decryptedData[bytesDecrypted]), &dDataSize, &(encryptedData[bytesProcessed]), &eDataSize))
        {
            LE_ERROR("Error decrypting string.");
            return LE_FAULT;
        }

        bytesProcessed += eDataSize; // Should be the same as get encrypted size.
        bytesDecrypted += dDataSize;

        if (bytesDecrypted > *decryptedDataSizePtr)
        {
            return LE_OVERFLOW;
        }
    }
    while (bytesProcessed < encryptedDataSize);

    *decryptedDataSizePtr = bytesDecrypted;

    return LE_OK;
}


COMPONENT_INIT
{
}