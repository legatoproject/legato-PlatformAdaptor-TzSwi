/**
 * @file pa_iksWrappers.c
 *
 * Implementation of @ref c_pa_iks API.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"
#include "interfaces.h"
#include "iks_keyStore.h"
#include "pa_iotKeystore.h"

#define PTR_TO_UINT64(x) ((uint64_t) (uintptr_t) (x))
#define UINT64_TO_PTR(x) ((void *) (uintptr_t) (x))

//--------------------------------------------------------------------------------------------------
/**
 * Convert IoT Keystore library result code to Legato result code.
 *
 * @return
 *      Legato result.
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ConvertRc
(
    iks_result_t iksRc  //< [IN] IoT Keystore result code.
)
{
    switch (iksRc)
    {
        case IKS_OK:
            return LE_OK;
        case IKS_INVALID_REF:
        case IKS_INVALID_PARAM:
        case IKS_INVALID_KEY:
            return LE_BAD_PARAMETER;
        case IKS_OVERFLOW:
            return LE_OVERFLOW;
        case IKS_NOT_FOUND:
            return LE_NOT_FOUND;
        case IKS_OUT_OF_RANGE:
            return LE_OUT_OF_RANGE;
        case IKS_OUT_OF_MEMORY:
            return LE_NO_MEMORY;
        case IKS_FORMAT_ERROR:
            return LE_FORMAT_ERROR;
        default:
            return LE_FAULT;
    }
}


//========================= Key Management routines =====================


//--------------------------------------------------------------------------------------------------
/**
 * Sets the module ID.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_SetModuleId
(
    const char*     idPtr,      ///< [IN] Identifier string.
    uint64_t        keyRef      ///< [IN] Key reference.
)
{
    return ConvertRc(iks_SetModuleId(idPtr, UINT64_TO_PTR(keyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets the module ID.
 *
 * @return
 *      LE_OK
 *      LE_NOT_FOUND
 *      LE_BAD_PARAMETER
 *      LE_OVERFLOW
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetModuleId
(
    char*       idPtr,        ///< [OUT] Module ID buffer.
    size_t      idPtrSize     ///< [IN] Module ID buffer size.
)
{
    return ConvertRc(iks_GetModuleId(idPtr, idPtrSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Deletes the module ID.
 *
 * @return
 *      LE_OK
 *      LE_NOT_FOUND
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_DeleteModuleId
(
    const uint8_t*  authCmdPtr,     ///< [IN] Authenticated command buffer.
    size_t          authCmdSize     ///< [IN] Authenticated command buffer size.
)
{
    return ConvertRc(iks_DeleteModuleId(authCmdPtr, authCmdSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets a reference to a key.
 *
 * @return
 *      Reference to the key.
 *      0 if the key could not be found.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_GetKey
(
    const char*     keyId           ///< [IN] Identifier string.
)
{
    return PTR_TO_UINT64(iks_GetKey(keyId));
}


//--------------------------------------------------------------------------------------------------
/**
 * Creates a new key.
 *
 * @return
 *      Reference to the key if successful.
 *      0 if the keyId is already being used or is invalid or the keyUsage is invalid.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_CreateKey
(
    const char*         keyId,      ///< [IN] Identifier string.
    uint32_t            keyUsage    ///< [IN] Key usage.
)
{
    return PTR_TO_UINT64(iks_CreateKey(keyId, keyUsage));
}


//--------------------------------------------------------------------------------------------------
/**
 * Creates a new key of a specific type.
 *
 * @return
 *      Reference to the key if successful.
 *      0 if the keyId is already being used or if there was some other error.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_CreateKeyByType
(
    const char*         keyId,      ///< [IN] Identifier string.
    int32_t             keyType,    ///< [IN] Key type.
    uint32_t            keySize     ///< [IN] Key size in bytes.
)
{
    return PTR_TO_UINT64(iks_CreateKeyByType(keyId, keyType, keySize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Get the key type.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetKeyType
(
    uint64_t            keyRef,     ///< [IN] Key reference.
    int32_t*            keyTypePtr  ///< [OUT] Key type.
)
{
    iks_KeyType_t  keyType = 0;
    le_result_t rc = ConvertRc(iks_GetKeyType((iks_KeyRef_t) (uintptr_t) keyRef, &keyType));
    *keyTypePtr = keyType;

    return rc;
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets the key size in bytes.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetKeySize
(
    uint64_t            keyRef,     ///< [IN] Key reference.
    uint32_t*           keySizePtr  ///< [OUT] Key size.
)
{
    return ConvertRc(iks_GetKeySize(UINT64_TO_PTR(keyRef), keySizePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Checks if the key size is valid.
 *
 * @return
 *      LE_OK
 *      LE_OUT_OF_RANGE
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_IsKeySizeValid
(
    int32_t             keyType,    ///< [IN] Key type.
    uint32_t            keySize     ///< [IN] Key size in bytes.
)
{
    return ConvertRc(iks_IsKeySizeValid(keyType, keySize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Checks if the key has a value.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_NOT_FOUND
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_HasKeyValue
(
    uint64_t        keyRef          ///< [IN] Key reference.
)
{
    return ConvertRc(iks_HasKeyValue(UINT64_TO_PTR(keyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Set an update key for the specified key.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_SetKeyUpdateKey
(
    uint64_t        keyRef,         ///< [IN] Key reference.
    uint64_t        updateKeyRef    ///< [IN] Reference to an update key.
)
{
    return ConvertRc(iks_SetKeyUpdateKey(UINT64_TO_PTR(keyRef), UINT64_TO_PTR(updateKeyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Generate a key value.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GenKeyValue
(
    uint64_t        keyRef,         ///< [IN] Key reference.
    const uint8_t*  authCmdPtr,     ///< [IN] Authenticated command buffer.
    size_t          authCmdSize     ///< [IN] Authenticated command buffer size.
)
{
    return ConvertRc(iks_GenKeyValue(UINT64_TO_PTR(keyRef), authCmdPtr, authCmdSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Provision a key value.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_ProvisionKeyValue
(
    uint64_t        keyRef,             ///< [IN] Key reference.
    const uint8_t*  provPackagePtr,     ///< [IN] Provisioning package.
    size_t          provPackageSize     ///< [IN] Provisioning package size.
)
{
    return ConvertRc(iks_ProvisionKeyValue(UINT64_TO_PTR(keyRef), (uint8_t *) provPackagePtr,
                                           provPackageSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Saves a key to persistent storage.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_SaveKey
(
    uint64_t        keyRef  ///< [IN] Key reference.
)
{
    return ConvertRc(iks_SaveKey(UINT64_TO_PTR(keyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Delete key.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_DeleteKey
(
    uint64_t        keyRef,         ///< [IN] Key reference.
    const uint8_t*  authCmdPtr,     ///< [IN] Authenticated command buffer.
    size_t          authCmdSize     ///< [IN] Authenticated command buffer size.
)
{
    return ConvertRc(iks_DeleteKey(UINT64_TO_PTR(keyRef), authCmdPtr, authCmdSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Get the public portion of an asymmetric key.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_NOT_FOUND
 *      LE_UNSUPPORTED
 *      LE_OVERFLOW
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetPubKeyValue
(
    uint64_t        keyRef,     ///< [IN] Key reference.
    uint8_t*        bufPtr,     ///< [OUT] Buffer to hold key value.
    size_t*         bufSizePtr  ///< [INOUT] Key value buffer size.
)
{
    return ConvertRc(iks_GetPubKeyValue(UINT64_TO_PTR(keyRef), bufPtr, bufSizePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets a reference to a digest.
 *
 * @return
 *      Reference to the digest.
 *      0 if the digest could not be found.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_GetDigest
(
    const char* digestId ///< [IN] Identifier string.
)
{
    return PTR_TO_UINT64(iks_GetDigest(digestId));
}


//--------------------------------------------------------------------------------------------------
/**
 * Creates a new digest.
 *
 * @return
 *      Reference to the digest if successful.
 *      0 if there was an error.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_CreateDigest
(
    const char*     digestId,   ///< [IN] Identifier string.
    uint32_t        digestSize  ///< [IN] Digest size. Must be <= MAX_DIGEST_SIZE.
)
{
    return PTR_TO_UINT64(iks_CreateDigest(digestId, digestSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Gets the digest size in bytes.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetDigestSize
(
    uint64_t            digestRef,      ///< [IN] Digest reference.
    uint32_t*           digestSizePtr   ///< [OUT] Digest size.
)
{
    return ConvertRc(iks_GetDigestSize(UINT64_TO_PTR(digestRef), digestSizePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Set an update key for the specified digest.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_SetDigestUpdateKey
(
    uint64_t            digestRef,      ///< [IN] Digest reference.
    uint64_t            updateKeyRef    ///< [IN] Reference to an update key.
)
{
    return ConvertRc(iks_SetDigestUpdateKey(UINT64_TO_PTR(digestRef), UINT64_TO_PTR(updateKeyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Provision a digest value.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_ProvisionDigest
(
    uint64_t            digestRef,      ///< [IN] Digest reference.
    const uint8_t*      provPackagePtr, ///< [IN] Provisioning package.
    size_t              provPackageSize ///< [IN] Provisioning package size.
)
{
    return ConvertRc(iks_ProvisionDigest(UINT64_TO_PTR(digestRef), (uint8_t *) provPackagePtr,
                                         provPackageSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Saves a digest to persistent storage.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_SaveDigest
(
    uint64_t            digestRef   ///< [IN] Digest reference.
)
{
    return ConvertRc(iks_SaveDigest(UINT64_TO_PTR(digestRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Delete a digest.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_DeleteDigest
(
    uint64_t            digestRef,  ///< [IN] Digest reference.
    const uint8_t*      authCmdPtr, ///< [IN] Authenticated command buffer.
    size_t              authCmdSize ///< [IN] Authenticated command buffer size.
)
{
    return ConvertRc(iks_DeleteDigest(UINT64_TO_PTR(digestRef), authCmdPtr, authCmdSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Get the digest value.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_NOT_FOUND
 *      LE_OVERFLOW
 *      LE_UNSUPPORTED
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetDigestValue
(
    uint64_t            digestRef,  ///< [IN] Digest reference.
    uint8_t*            bufPtr,     ///< [OUT] Buffer to hold the digest value.
    size_t*             bufSizePtr  ///< [INOUT] Size of the buffer.
)
{
    return ConvertRc(iks_GetDigestValue(UINT64_TO_PTR(digestRef), bufPtr, bufSizePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Get update authentication challenge.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_GetUpdateAuthChallenge
(
    uint64_t            keyRef,     ///< [IN] Key reference.
    uint8_t*            bufPtr,     ///< [OUT] Buffer to hold the authentication challenge.
    size_t*             bufSizePtr  ///< [INOUT] Size of the authentication challenge buffer.
)
{
    LE_ASSERT(bufSizePtr != NULL);
    LE_ASSERT(*bufSizePtr >= IKS_CHALLENGE_SIZE);
    return ConvertRc(iks_GetUpdateAuthChallenge(UINT64_TO_PTR(keyRef), bufPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Get the provisioning key.
 *
 * @return
 *      LE_OK
 *      LE_OVERFLOW
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------


le_result_t pa_iks_GetProvisionKey
(
    uint8_t*    bufPtr,     ///< [OUT] Buffer to hold the provisioning key.
    size_t*     bufSizePtr  ///< [INOUT] Size of the buffer to hold the provisioning key.
)
{
    return ConvertRc(iks_GetProvisionKey(bufPtr, bufSizePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Create a session.
 *
 * @return
 *      A session reference if successful.
 *      0 if the key reference is invalid or does not contain a key value.
 */
//--------------------------------------------------------------------------------------------------
uint64_t pa_iks_CreateSession
(
    uint64_t            keyRef      ///< [IN] Key reference.
)
{
    return PTR_TO_UINT64(iks_CreateSession(UINT64_TO_PTR(keyRef)));
}


//--------------------------------------------------------------------------------------------------
/**
 * Delete a session.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_DeleteSession
(
    uint64_t            sessionRef  ///< [IN] Session reference.
)
{
    return ConvertRc(iks_DeleteSession(UINT64_TO_PTR(sessionRef)));
}


//========================= AES Milenage routines =====================


//--------------------------------------------------------------------------------------------------
/**
 * Calculates the network authentication code MAC-A using the Milenage algorithm set with AES-128 as
 * the block cipher.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesMilenage_GetMacA
(
    uint64_t        kRef,           ///< [IN] Reference to K.
    uint64_t        opcRef,         ///< [IN] Reference to OPc.
    const uint8_t*  randPtr,        ///< [IN] RAND challenge.
    size_t          randSize,       ///< [IN] RAND size.
    const uint8_t*  amfPtr,         ///< [IN] Authentication management field, AMF.
    size_t          amfSize,        ///< [IN] AMF size.
    const uint8_t*  sqnPtr,         ///< [IN] Sequence number, SQN.
    size_t          sqnSize,        ///< [IN] SQN size.
    uint8_t*        macaPtr,        ///< [OUT] Buffer to hold the network authentication code.
    size_t*         macaSizePtr     ///< [OUT] Network authentication code size.
)
{
    LE_ASSERT(randSize >= IKS_AES_MILENAGE_RAND_SIZE);
    LE_ASSERT(amfSize >= IKS_AES_MILENAGE_AMF_SIZE);
    LE_ASSERT(sqnSize >= IKS_AES_MILENAGE_SQN_SIZE);
    LE_ASSERT(macaSizePtr != NULL);
    LE_ASSERT(*macaSizePtr >= IKS_AES_MILENAGE_MACA_SIZE);

    return ConvertRc(iks_aesMilenage_GetMacA(UINT64_TO_PTR(kRef), UINT64_TO_PTR(opcRef),
                                             randPtr, amfPtr, sqnPtr, macaPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Calculates the re-synchronisation authentication code MAC-S using the Milenage algorithm set with
 * AES-128 as the block cipher.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesMilenage_GetMacS
(
    uint64_t        kRef,           ///< [IN] Reference to K.
    uint64_t        opcRef,         ///< [IN] Reference to OPc.
    const uint8_t*  randPtr,        ///< [IN] RAND challenge.
    size_t          randSize,       ///< [IN] RAND size.
    const uint8_t*  amfPtr,         ///< [IN] Authentication management field, AMF.
    size_t          amfSize,        ///< [IN] AMF size.
    const uint8_t*  sqnPtr,         ///< [IN] Sequence number, SQN.
    size_t          sqnSize,        ///< [IN] SQN size.
    uint8_t*        macsPtr,        ///< [OUT] Buffer to hold the re-sync authentication code.
    size_t*         macsSizePtr     ///< [OUT] Re-sync authentication code size.
)
{
    LE_ASSERT(randSize >= IKS_AES_MILENAGE_RAND_SIZE);
    LE_ASSERT(amfSize >= IKS_AES_MILENAGE_AMF_SIZE);
    LE_ASSERT(sqnSize >= IKS_AES_MILENAGE_SQN_SIZE);
    LE_ASSERT(macsSizePtr != NULL);
    LE_ASSERT(*macsSizePtr >= IKS_AES_MILENAGE_MACS_SIZE);

    return ConvertRc(iks_aesMilenage_GetMacS(UINT64_TO_PTR(kRef), UINT64_TO_PTR(opcRef),
                                             randPtr, amfPtr, sqnPtr, macsPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Derives authentication response and keys using the Milenage algorithm set with AES-128 as the
 * block cipher.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesMilenage_GetKeys
(
    uint64_t        kRef,           ///< [IN] Reference to K.
    uint64_t        opcRef,         ///< [IN] Reference to OPc.
    const uint8_t*  randPtr,        ///< [IN] RAND challenge.
    size_t          randSize,       ///< [IN] RAND size.
    uint8_t*        resPtr,         ///< [OUT] Buffer to hold the authentication response RES.
    size_t*         resSizePtr,     ///< [OUT] RES size.
    uint8_t*        ckPtr,          ///< [OUT] Buffer to hold the confidentiality key CK.
    size_t*         ckSizePtr,      ///< [OUT] CK size.
    uint8_t*        ikPtr,          ///< [OUT] Buffer to hold the integrity key IK.
    size_t*         ikSizePtr,      ///< [OUT] IK size.
    uint8_t*        akPtr,          ///< [OUT] Buffer to hold the anonymity key AK.
    size_t*         akSizePtr       ///< [OUT] AK size.
)
{
    LE_ASSERT(randSize >= IKS_AES_MILENAGE_RAND_SIZE);
    LE_ASSERT(resSizePtr != NULL);
    LE_ASSERT(*resSizePtr >= IKS_AES_MILENAGE_RES_SIZE);
    LE_ASSERT(ckSizePtr != NULL);
    LE_ASSERT(*ckSizePtr >= IKS_AES_MILENAGE_CK_SIZE);
    LE_ASSERT(ikSizePtr != NULL);
    LE_ASSERT(*ikSizePtr >= IKS_AES_MILENAGE_IK_SIZE);
    LE_ASSERT(akSizePtr != NULL);
    LE_ASSERT(*akSizePtr >= IKS_AES_MILENAGE_AK_SIZE);

    return ConvertRc(iks_aesMilenage_GetKeys(UINT64_TO_PTR(kRef), UINT64_TO_PTR(opcRef),
                                             randPtr, resPtr, ckPtr, ikPtr, akPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Derives the anonymity key for the re-synchronisation message using the Milenage algorithm set
 * with AES-128 as the block cipher.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_UNSUPPORTED
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesMilenage_GetAk
(
    uint64_t        kRef,           ///< [IN] Reference to K.
    uint64_t        opcRef,         ///< [IN] Reference to OPc.
    const uint8_t*  randPtr,        ///< [IN] RAND challenge.
    size_t          randSize,       ///< [IN] RAND size.
    uint8_t*        akPtr,          ///< [OUT] Buffer to hold the anonymity key AK.
    size_t*         akSizePtr       ///< [OUT] AK size.
)
{
    LE_ASSERT(randSize >= IKS_AES_MILENAGE_RAND_SIZE);
    LE_ASSERT(akSizePtr != NULL);
    LE_ASSERT(*akSizePtr >= IKS_AES_MILENAGE_AK_SIZE);

    return ConvertRc(iks_aesMilenage_GetAk(UINT64_TO_PTR(kRef), UINT64_TO_PTR(opcRef),
                                           randPtr, akPtr));
}


//========================= AES GCM routines =====================


//--------------------------------------------------------------------------------------------------
/**
 * Encrypt and integrity protect a packet with AES in GCM mode.
 *
 * @return
 *      LE_OK
 *      LE_OUT_OF_RANGE
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_EncryptPacket
(
    uint64_t        keyRef,             ///< [IN] Key reference.
    uint8_t*        noncePtr,           ///< [OUT] Buffer to hold the nonce.
    size_t*         nonceSizePtr,       ///< [INOUT] Nonce size.
    const uint8_t*  aadPtr,             ///< [IN] Additional authenticated data (AAD).
    size_t          aadSize,            ///< [IN] AAD size.
    const uint8_t*  plaintextPtr,       ///< [IN] Plaintext. NULL if not used.
    size_t          plaintextSize,      ///< [IN] Plaintext size.
    uint8_t*        ciphertextPtr,      ///< [OUT] Buffer to hold the ciphertext.
    size_t*         ciphertextSizePtr,  ///< [INOUT] Ciphertext size.
    uint8_t*        tagPtr,             ///< [OUT] Buffer to hold the authentication tag.
    size_t*         tagSizePtr          ///< [INOUT] Authentication tag size.
)
{
    LE_ASSERT(noncePtr != NULL);
    LE_ASSERT(nonceSizePtr != NULL);
    LE_ASSERT(*nonceSizePtr >= IKS_AES_GCM_NONCE_SIZE);
    LE_ASSERT(tagPtr != NULL);
    LE_ASSERT(tagSizePtr != NULL);
    LE_ASSERT(*tagSizePtr >= IKS_AES_GCM_TAG_SIZE);

    iks_result_t iksRc = iks_aesGcm_EncryptPacket(UINT64_TO_PTR(keyRef), noncePtr,
                                                  aadPtr, aadSize,
                                                  plaintextPtr, ciphertextPtr,
                                                  plaintextSize, tagPtr);
    if (iksRc == IKS_OK)
    {
        // Plaintext and ciphertext have the same size.
        *ciphertextSizePtr = plaintextSize;
        *nonceSizePtr = IKS_AES_GCM_NONCE_SIZE;
        *tagSizePtr = IKS_AES_GCM_TAG_SIZE;
    }
    return ConvertRc(iksRc);
}


//--------------------------------------------------------------------------------------------------
/**
 * Decrypt and verify the integrity of a packet with AES in GCM mode.
 *
 * @return
 *      LE_OK
 *      LE_OUT_OF_RANGE
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_DecryptPacket
(
    uint64_t        keyRef,             ///< [IN] Key reference.
    const uint8_t*  noncePtr,           ///< [IN] Nonce used to encrypt the packet.
    size_t          nonceSize,          ///< [IN] Nonce size.
    const uint8_t*  aadPtr,             ///< [IN] Additional authenticated data (AAD).
    size_t          aadSize,            ///< [IN] AAD size.
    const uint8_t*  ciphertextPtr,      ///< [IN] Ciphertext. NULL if not used.
    size_t          ciphertextSize,     ///< [IN] Ciphertext size.
    uint8_t*        plaintextPtr,       ///< [OUT] Buffer to hold the plaintext.
    size_t*         plaintextSizePtr,   ///< [INOUT] Plaintext size.
    const uint8_t*  tagPtr,             ///< [IN] Buffer to hold the authentication tag.
    size_t          tagSize             ///< [IN] Authentication tag size.
)
{

    LE_ASSERT(noncePtr != NULL);
    LE_ASSERT(nonceSize == IKS_AES_GCM_NONCE_SIZE);
    LE_ASSERT(tagPtr != NULL);
    LE_ASSERT(tagSize == IKS_AES_GCM_TAG_SIZE);

    iks_result_t iksRc = iks_aesGcm_DecryptPacket(UINT64_TO_PTR(keyRef), noncePtr, aadPtr, aadSize,
                                                  ciphertextPtr, plaintextPtr, *plaintextSizePtr,
                                                  tagPtr);
    if (iksRc == IKS_OK)
    {
        // Plaintext and ciphertext have the same size.
        *plaintextSizePtr = ciphertextSize;

    }
    return ConvertRc(iksRc);
}


//--------------------------------------------------------------------------------------------------
/**
 * Starts a process to encrypt and integrity protect a long packet with AES in GCM mode.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_StartEncrypt
(
    uint64_t    session,        ///< [IN] Session reference.
    uint8_t*    noncePtr,       ///< [OUT] Buffer to hold the nonce.  Assumed to be
                                ///<       LE_IKS_AES_GCM_NONCE_SIZE bytes.
    size_t*     nonceSizePtr    ///< [INOUT] Nonce size.
                                ///<         Expected to be LE_IKS_AESGCM_NONCE_SIZE.
)
{
    LE_ASSERT(noncePtr != NULL);
    LE_ASSERT(nonceSizePtr != NULL);
    LE_ASSERT(*nonceSizePtr >= IKS_AES_GCM_NONCE_SIZE);

    return ConvertRc(iks_aesGcm_StartEncrypt(UINT64_TO_PTR(session), noncePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Process a chunk of AAD (Additional Authenticated Data).
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_OUT_OF_RANGE
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_ProcessAad
(
    uint64_t        session,        ///< [IN] Session reference.
    const uint8_t*  aadChunkPtr,    ///< [IN] AAD chunk.
    size_t          aadChunkSize    ///< [IN] AAD chunk size.  Must be <= LE_IKS_MAX_PACKET_SIZE.
)
{
    return ConvertRc(iks_aesGcm_ProcessAad(UINT64_TO_PTR(session), aadChunkPtr, aadChunkSize));
}


//--------------------------------------------------------------------------------------------------
/**
 * Encrypt a chunk of plaintext.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_OUT_OF_RANGE
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_Encrypt
(
    uint64_t        session,                ///< [IN] Session reference.
    const uint8_t*  plaintextChunkPtr,      ///< [IN] Plaintext chunk.
    size_t          plaintextChunkSize,     ///< [IN] Plaintext chunk size.
    uint8_t*        ciphertextChunkPtr,     ///< [OUT] Buffer to hold the ciphertext chunk.
    size_t*         ciphertextChunkSizePtr  ///< [INOUT] Ciphertext chunk size.
                                            ///<         Must be >= plaintextChunkSize.
)
{
    LE_ASSERT(plaintextChunkPtr != NULL);
    LE_ASSERT(ciphertextChunkPtr != NULL);
    LE_ASSERT(ciphertextChunkSizePtr != NULL);
    LE_ASSERT(*ciphertextChunkSizePtr >= plaintextChunkSize);

    iks_result_t iksRc = iks_aesGcm_Encrypt(UINT64_TO_PTR(session), plaintextChunkPtr,
                                            ciphertextChunkPtr, plaintextChunkSize);
    if (iksRc == IKS_OK)
    {
        // Plaintext and ciphertext have the same size.
        *ciphertextChunkSizePtr = plaintextChunkSize;
    }
    return ConvertRc(iksRc);
}


//--------------------------------------------------------------------------------------------------
/**
 * Complete encryption and calculate the authentication tag.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_DoneEncrypt
(
    uint64_t    session,        ///< [IN] Session reference.
    uint8_t*    tagPtr,         ///< [OUT] Buffer to hold the authentication tag.
    size_t*     tagSizePtr      ///< [INOUT] Authentication tag size.
                                ///<         Expected to be LE_IKS_AESGCM_TAG_SIZE.
)
{
    LE_ASSERT(tagPtr != NULL);
    LE_ASSERT(tagSizePtr != NULL);
    LE_ASSERT(*tagSizePtr >= IKS_AES_GCM_TAG_SIZE);

    return ConvertRc(iks_aesGcm_DoneEncrypt(UINT64_TO_PTR(session), tagPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Starts a process to decrypt and verify the integrity of a long packet with AES in GCM mode.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_StartDecrypt
(
    uint64_t        session,        ///< [IN] Session reference.
    const uint8_t*  noncePtr,       ///< [IN] Nonce used to encrypt the packet.
    size_t          nonceSize       ///< [IN] Nonce size.
                                    ///<         Expected to be LE_IKS_AESGCM_NONCE_SIZE.
)
{
    return ConvertRc(iks_aesGcm_StartDecrypt(UINT64_TO_PTR(session), noncePtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Decrypt a chunk of ciphertext.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_OUT_OF_RANGE
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_Decrypt
(
    uint64_t        session,                ///< [IN] Session reference.
    const uint8_t*  ciphertextChunkPtr,     ///< [IN] Ciphertext chunk.
    size_t          ciphertextChunkSize,    ///< [IN] Ciphertext chunk size.
    uint8_t*        plaintextChunkPtr,      ///< [OUT] Buffer to hold the plaintext chunk.
    size_t*         plaintextChunkSizePtr   ///< [INOUT] Plaintext chunk size.
                                            ///<         Must be >= ciphertextSize.
)
{
    LE_ASSERT(ciphertextChunkPtr != NULL);
    LE_ASSERT(plaintextChunkPtr != NULL);
    LE_ASSERT(plaintextChunkSizePtr != NULL);
    LE_ASSERT(*plaintextChunkSizePtr >= ciphertextChunkSize);

    iks_result_t iksRc = iks_aesGcm_Decrypt(UINT64_TO_PTR(session), ciphertextChunkPtr,
                                            plaintextChunkPtr, ciphertextChunkSize);
    if (iksRc == IKS_OK)
    {
        // Plaintext and ciphertext have the same size.
        *plaintextChunkSizePtr = ciphertextChunkSize;
    }

    return ConvertRc(iksRc);
}


//--------------------------------------------------------------------------------------------------
/**
 * Complete decryption and verify the integrity.
 *
 * @return
 *      LE_OK
 *      LE_BAD_PARAMETER
 *      LE_FAULT
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_iks_aesGcm_DoneDecrypt
(
    uint64_t        session,    ///< [IN] Session reference.
    const uint8_t*  tagPtr,     ///< [IN] Buffer to hold the authentication tag.
    size_t          tagSize     ///< [IN] Authentication tag size.
                                ///<         Expected to be LE_IKS_AESGCM_TAG_SIZE.
)
{
    return ConvertRc(iks_aesGcm_DoneDecrypt(UINT64_TO_PTR(session), tagPtr));
}


//--------------------------------------------------------------------------------------------------
/**
 * Init this component
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
}
