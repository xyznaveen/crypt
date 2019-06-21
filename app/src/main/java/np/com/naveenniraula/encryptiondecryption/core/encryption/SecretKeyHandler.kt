package np.com.naveenniraula.encryptiondecryption.core.encryption

import android.os.AsyncTask
import android.util.Base64
import android.util.Log
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class SecretKeyHandler private constructor() {

    enum class KeyLength(val size: Int) {
        K128(128), K256(256)
    }

    private lateinit var keyGenerationCompleteListener: KeyGenerationCompleteListener

    private lateinit var password: String
    private lateinit var salt: SecretKeySalt
    private var keySize: Int = KeyLength.K128.size

    // Number of PBKDF2 hardening rounds to use. Larger values increase
    // computation time. You should select a value that causes computation
    // to take >100ms.
    // 100,000 iterations take 6 seconds on J7 Prime; don't increase this any further. :D
    private var iterations: Int = 100_000

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun generateKey(passphraseOrPin: String, salt: ByteArray): SecretKeySpec {

        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keySpec = PBEKeySpec(passphraseOrPin.toCharArray(), salt, iterations, keySize)
        val keySpecFromFactory = secretKeyFactory.generateSecret(keySpec)

        Log.i("BQ7CH72", "Secrett :: ${Base64.encodeToString(keySpecFromFactory?.encoded, Base64.NO_PADDING)}")

        return SecretKeySpec(keySpecFromFactory.encoded, "AES")
    }

    class Builder {

        private val secretKeyHandler = SecretKeyHandler()

        fun withPassword(password: String): Builder {

            secretKeyHandler.password = password
            return this
        }

        fun withDefaultParams(): Builder {

            withDefaultSalt()
            withKeyLength(SecretKeyHandler.KeyLength.K256)
            return this
        }

        fun withKey(key: String = ""): Builder {

            secretKeyHandler.salt = SecretKeySalt.getInstance(key)
            return this
        }

        fun withNewSalt(keySize: Int): Builder {
            secretKeyHandler.salt = SecretKeySalt.getInstance(keySize)
            return this
        }

        fun withDefaultSalt(): Builder {
            secretKeyHandler.salt = SecretKeySalt.getInstance()
            return this
        }

        fun withSalt(salt: SecretKeySalt): Builder {
            secretKeyHandler.salt = salt
            return this
        }

        fun withKeyLength(keyLength: KeyLength): Builder {
            secretKeyHandler.keySize = keyLength.size
            return this
        }

        fun withIterations(iterations: Int = 100_000): Builder {

            secretKeyHandler.iterations = if (iterations > 100_000) 100_000 else iterations
            return this
        }

        fun onKeyGenerationComplete(keyGenerationCompleteListener: KeyGenerationCompleteListener): Builder {
            secretKeyHandler.keyGenerationCompleteListener = keyGenerationCompleteListener
            return this
        }

        fun build(): SecretKeyHandler {

            // start key generation task as soon as the object is built
            secretKeyHandler.prepareKeyAsync()

            return secretKeyHandler
        }

    }

    /**
     * Generate encryption key.
     */
    private fun prepareKeyAsync() {
        val kga = KeyGeneratorAsync(password, salt.getBytes())
        kga.setOnKeyGenerationCompleteListener(keyGenerationCompleteListener)
        kga.execute()
    }

    @SuppressWarnings("StaticFieldLeak")
    inner class KeyGeneratorAsync private constructor() : AsyncTask<Any, Any, SecretKeySpec>() {

        lateinit var listener: KeyGenerationCompleteListener
        lateinit var passphraseOrPin: String
        lateinit var salt: ByteArray

        constructor(passphraseOrPin: String, salt: ByteArray) : this() {
            this.passphraseOrPin = passphraseOrPin
            this.salt = salt
        }

        override fun doInBackground(vararg params: Any?): SecretKeySpec {

            return generateKey(passphraseOrPin, salt)
        }

        override fun onPostExecute(result: SecretKeySpec?) {
            super.onPostExecute(result)

            result?.let {
                listener.onKeyGenerationComplete(it, SecretKeySalt.getInstance(salt))
            }
        }

        fun setOnKeyGenerationCompleteListener(listener: KeyGenerationCompleteListener) {
            this.listener = listener
        }

    }

    interface KeyGenerationCompleteListener {
        fun onKeyGenerationComplete(key: SecretKeySpec, salt: SecretKeySalt)
    }

}