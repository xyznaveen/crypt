package np.com.naveenniraula.encryptiondecryption.core.encryption

import android.util.Base64

import java.security.SecureRandom

class SecretKeySalt private constructor() {

    private lateinit var keyBytes: ByteArray
    private lateinit var keyString: String
    private lateinit var password: String

    constructor(keyString: String) : this() {
        this.keyString = keyString
        keyBytes = getBytesFromString(keyString)
    }

    constructor(keySize: Int) : this() {
        keyBytes = SecureRandom().generateSeed(keySize)
        keyString = Base64.encodeToString(keyBytes, Base64.NO_PADDING)
    }

    constructor(bytes: ByteArray) : this() {
        keyBytes = bytes
        keyString = Base64.encodeToString(keyBytes, Base64.NO_PADDING)
    }

    override fun toString(): String {
        return getStringFromBytes(keyBytes)
    }

    private fun getStringFromBytes(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.NO_PADDING)
    }

    private fun getBytesFromString(string: String): ByteArray {
        return Base64.decode(string, Base64.NO_PADDING)
    }

    fun getBytes(): ByteArray {
        return keyBytes
    }

    companion object {

        fun getInstance(keySize: Int = 16): SecretKeySalt {
            return SecretKeySalt(keySize)
        }

        fun getInstance(keyString: String): SecretKeySalt {
            return SecretKeySalt(keyString)
        }

        fun getInstance(bytes: ByteArray): SecretKeySalt {
            return SecretKeySalt(bytes)
        }

    }

    class Builder {
        private val encryptionSecretKey = SecretKeySalt()

        fun withPassword(password: String): Builder {
            encryptionSecretKey.password = password
            return this
        }

        fun withKey() {

        }

    }


}