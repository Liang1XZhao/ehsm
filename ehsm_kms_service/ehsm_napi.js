const ffi = require('ffi-napi')

const ehsm_napi = ffi.Library('./libehsmnapi', {
  /**
    create the enclave
  */
  NAPI_Initialize: ['string', []],

  /**
    destory the enclave
  */
  NAPI_Finalize: ['string', []],

  /**
    NAPI_CreateKey
    Description:
      Create a customer master key with the following metadatas

    .keyspec;
      -EH_AES_GCM_128,
      -EH_AES_GCM_256,
      -EH_RSA_2048,
      -EH_RSA_3072,
      -EH_EC_P256,
      -EH_EC_P512,
      -EH_EC_SM2,
      -EH_SM4,
    .origin;
      -EH_INTERNAL_KEY (generated from the eHSM inside)
      -EXTERNAL_KEY (generated by the customer and want to import into the eHSM),
    .purpose;
      -ENCRYPT_DECRYPT,
      -SIGN_VERIFY,
    .apiversion;
      -Reserved
    .descrption;
      -Reserved
    .createdate
      -Reserved
    Note: the CMK will be wrapped by the DK(DomainKey)

    params 
      - keyspec: int
      - origin: int
    
    return json
      {
        code: int,
        message: string,
        result: {
          cmk_base64: string,
        }
      }
  */
  NAPI_CreateKey: ['string', ['int', 'int']],

  /**
    NAPI_Encrypt 
    Description:
      Encrypt an arbitrary set of bytes using the CMK.(only support symmetric types)

    params
      - cmk_base64: string
      - plaintext: string
      - aad: string
    
    return json
      {
        code: int,
        message: string,
        result: {
          cipherText_base64 : string,
        }
      }
  */
  NAPI_Encrypt: ['string', ['string', 'string', 'string']],

  /**
    NAPI_Decrypt 
    Description:
      Decrypts ciphertext using the CMK.(only support symmetric types)

    params
      - cmk_base64: string
      - ciphertext: string
      - aad: string
    
    return json
      {
        code: int,
        message: string,
        result: {
          plaintext_base64 : string,
        }
      }
  */
  NAPI_Decrypt: ['string', ['string', 'string', 'string']],

  /**
    NAPI_GenerateDataKey 
    Description:
      Generates a random data key that is used to locally encrypt data.
      the datakey will be wrapped by the specified CMK(only support asymmetric keyspec),
      and it will return the plaintext and ciphertext of the data key.
      You can use the plaintext of the data key to locally encrypt your data without using KMS
      and store the encrypted data together with the ciphertext of the data key, then clear the
      plaintext data from memory as soon as possible.
      when you want to obtain the plaintext of datakey again, you can call the Decrypt with the
      cmk to get the plaintext data.

    params 
      - cmk_base64: string
      - keylen： number
      - aad: string
      
    return json
      {
        code: int,
        message: string,
        result: {
          plaintext_base64 : string,
          cipherText_base64 : string,
        }
      }
  */
  NAPI_GenerateDataKey: ['string', ['string', 'int', 'string']],

  /**
    NAPI_GenerateDataKeyWithoutPlaintext
    Description:
      The same as GenerateDataKey, but doesn’t return plaintext of generated DataKey.

    params 
      - cmk_base64: string
      - keylen： number
      - aad: string
      
    return json
      {
        code: int,
        message: string,
        result: {
          ciphertext_base64 : string,
        }
      }
  */
  NAPI_GenerateDataKeyWithoutPlaintext: ['string', ['string', 'int', 'string']],

  /**
    NAPI_Sign
    Description:
    Performs sign operation using the cmk(only support asymmetric keyspec).

    params:
      - cmk_base64: string
      - digest: string

    return json
      {
        code: int,
        message: string,
        result: {
          signature_base64: string
        }
      }
  */
  NAPI_Sign: ['string', ['string', 'string']],

  /**
  NAPI_Verify
  Description:
    Performs verify operation using the cmk(only support asymmetric keyspec).

  params:
    - cmk_base64: string
    - digest string
    - signature: string

  return json
    {
      code: int,
      message: string,
      result: {
        result: bool
      }
    }
  */
  NAPI_Verify: ['string', ['string', 'string', 'string']],

  /**
    NAPI_AsymmetricEncrypt
    Description:
    Encrypt an arbitrary set of bytes using the CMK.(only support asymmetric types)

    params:
      - cmk_base64: string
      - plaintext: string
    
    return json
      {
        code: int,
        message: string,
        result: {
          ciphertext_base64: string
        }
      }
    Note:
    the data size is limited decided by the keyspec:
    RSA_OAEP_2048_SHA_256_MAX_ENCRYPTION_SIZE       190
    RSA_2048_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       214

    RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE       318
    RSA_3072_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       342

    SM2PKE_MAX_ENCRYPTION_SIZE                      6047
  */
  NAPI_AsymmetricEncrypt: ['string', ['string', 'string']],

  /**
    NAPI_AsymmetricDecrypt
    Description:
    Encrypt an arbitrary set of bytes using the CMK.(only support asymmetric types)

    params:
      - cmk_base64: string
      - ciphertext_base64: string
    
    return json
      {
        code: int,
        message: string,
        result: {
          plaintext_base64: string
        }
      }
    Note:
    the data size is limited decided by the keyspec:
    RSA_OAEP_2048_SHA_256_MAX_ENCRYPTION_SIZE       190
    RSA_2048_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       214

    RSA_OAEP_3072_SHA_256_MAX_ENCRYPTION_SIZE       318
    RSA_3072_OAEP_SHA_1_MAX_ENCRYPTION_SIZE       342

    SM2PKE_MAX_ENCRYPTION_SIZE                      6047
  */
  NAPI_AsymmetricDecrypt: ['string', ['string', 'string']],

  /**
  NAPI_ExportDataKey
  Description:
    ehsm-core enclave will decrypt user-supplied ciphertextblob with specified CMK to get the
    plaintext of DataKey, then use the user-supplied Public key to encrypt this DataKey
    (aka ExportedDataKey). This ExportedDataKey (ciphertext) will be returned to caller.
  params:
    - cmk_base64:
        des: A symmetric cmk
        type: string
    - ukey_base64:
        des: An asymmetric key
        type: string
    - aad: 
        des: some extra datas input by the user, which could help to to ensure data integrity
        type: string
    - olddatakey_base:
        des: the ciphertext of the datakey wrapped by the cmk
        type: string
  return json
    {
      code: int,
      message: string,
      result: {
        cipher_datakey_new_base64: string
      }
    }
  */
  NAPI_ExportDataKey: ['string', ['string', 'string', 'string', 'string']],

  NAPI_RA_HANDSHAKE_MSG0: ['string', ['string']],
})

module.exports = ehsm_napi
