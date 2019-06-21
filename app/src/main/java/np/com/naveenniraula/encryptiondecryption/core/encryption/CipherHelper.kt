package np.com.naveenniraula.encryptiondecryption.core.encryption

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class CipherHelper private constructor() {

    private lateinit var instance: Cipher

    fun getCipher(): Cipher {
        return instance
    }


    companion object {
        private fun getInstance(
            mode: Int = Cipher.ENCRYPT_MODE,
            key: SecretKeySpec,
            ivParameterSpec: IvParameterSpec
        ): CipherHelper {

            val cipherHelper = CipherHelper()
            cipherHelper.instance = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipherHelper.instance.init(mode, key, ivParameterSpec)
            return cipherHelper
        }

        /**
         * Gets the ready to use cipher for encryption mode.
         * @return
         */
        fun getEncryptionInstance(key: SecretKey, initVector: String): CipherHelper {
            return getInstance(Cipher.ENCRYPT_MODE, key as SecretKeySpec, IvParameterSpec(initVector.toByteArray()))
        }


        /**
         * Gets the ready to use cipher for decryption mode.
         * @return
         */
        fun getDecryptionInstance(key: SecretKey, initVector: String): CipherHelper {
            return getInstance(Cipher.DECRYPT_MODE, key as SecretKeySpec, IvParameterSpec(initVector.toByteArray()))
        }
    }

}