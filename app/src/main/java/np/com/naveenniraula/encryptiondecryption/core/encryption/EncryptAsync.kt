package np.com.naveenniraula.encryptiondecryption.core.encryption

import android.os.AsyncTask
import android.util.Base64
import android.util.Log
import java.io.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class EncryptAsync(private val inFileName: String, private val outFileName: String) :
    AsyncTask<Void, Long, EncryptAsync.CompletionType>() {

    // private val ivParameterSpec: IvParameterSpec
    private lateinit var secretKey: SecretKey
    private var encryptionMode: Int = 0

    enum class CompletionType {
        ERROR, SUCCESS, CANCELLED
    }

    private val inputFile: File = File(inFileName)
    private val outputFile: File = File(outFileName)
    private lateinit var encryptionProgressListener: EncryptionProgressListener

    override fun doInBackground(vararg p0: Void?): EncryptAsync.CompletionType {

        // could not open file
        if (!inputFile.exists()) {
            Log.i("BQ7CH72", "File was not found!")
            return CompletionType.ERROR
        }

        val fileInputStream = FileInputStream(inputFile)
        val fileOutputStream = FileOutputStream(outputFile)

        val fileSize = inputFile.length()

        // var buffer = ByteArray(BUFFER_LARGE)
        var actualSize: Long = 0
        var progress: Long
        var c = 0

        when (encryptionMode) {
            Cipher.ENCRYPT_MODE -> {

                val cipher = CipherHelper.getEncryptionInstance(secretKey, "passwordpassword").getCipher()
                // cipher!!.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
                val bufferedOutputStream = BufferedOutputStream(fileOutputStream)
                val cipherOutputStream = CipherOutputStream(bufferedOutputStream, cipher)
                do {
                    val myBuff = ByteArray(BUFFER_LARGE)
                    c = fileInputStream.read(myBuff, 0, BUFFER_LARGE)

                    if (c == -1) {
                        cipherOutputStream.close()
                        break
                    }

                    cipherOutputStream.write(myBuff, 0, c)
                    actualSize += c

                    // publish completion percentage
                    progress = (actualSize * 100.0 / fileSize + 0.5).toLong()
                    publishProgress(progress, actualSize, fileSize)
                } while (c > 0)
            }
            Cipher.DECRYPT_MODE -> {
                val cipher = CipherHelper.getDecryptionInstance(secretKey, "passwordpassword").getCipher()
                // cipher!!.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
                val bufferedInputStream = BufferedInputStream(fileInputStream)
                val cipherInputStream = CipherInputStream(bufferedInputStream, cipher)
                val bufferedOutputStream = BufferedOutputStream(fileOutputStream)
                do {
                    val myBuff = ByteArray(BUFFER_LARGE)
                    c = cipherInputStream.read(myBuff, 0, BUFFER_LARGE)

                    if (c == -1) {
                        cipherInputStream.close()
                        break
                    }

                    bufferedOutputStream.write(myBuff, 0, c)

                    actualSize += c

                    // publish completion percentage
                    progress = (actualSize * 100.0 / fileSize + 0.5).toLong()
                    publishProgress(progress, actualSize, fileSize)
                } while (c > 0)
            }
        }

        fileInputStream.close()
        fileOutputStream.close()

        return EncryptAsync.CompletionType.SUCCESS
    }

    override fun onProgressUpdate(vararg values: Long?) {
        super.onProgressUpdate(*values)

        // Log.i("BQ7CH72", "mode -> $encryptionMode")

        if (!isInitialized()) return
        values[0]?.let {
            encryptionProgressListener.onProgress(it)
        }
    }

    override fun onPostExecute(result: EncryptAsync.CompletionType) {
        super.onPostExecute(result)

        // notify whoever is listening
        if (!isInitialized()) return
        when (result) {
            CompletionType.SUCCESS -> encryptionProgressListener.onSuccess()
            CompletionType.ERROR -> encryptionProgressListener.onError("An error!")
            CompletionType.CANCELLED -> encryptionProgressListener.onError("User cancelled!")
        }
    }

    fun setEncryptionProgressListener(encryptionProgressListener: EncryptionProgressListener) {
        this.encryptionProgressListener = encryptionProgressListener
    }

    private fun isInitialized(): Boolean {
        return ::encryptionProgressListener.isInitialized
    }

    fun encrypt(password: String, passwordSalt: String) {

        SecretKeyHandler.Builder()
            .withPassword(password)
            .withSalt(SecretKeySalt.getInstance(passwordSalt))
            .withKeyLength(SecretKeyHandler.KeyLength.K256)
            .onKeyGenerationComplete(object : SecretKeyHandler.KeyGenerationCompleteListener {

                override fun onKeyGenerationComplete(key: SecretKeySpec, salt: SecretKeySalt) {

                    secretKey = key

                    Log.i("BQ7CH72", "encrypt key :: ${Base64.encodeToString(key.encoded, Base64.NO_PADDING)}")


                    if (isInitialized()) {
                        encryptionProgressListener.onKeyGenerated(
                            Base64.encodeToString(
                                secretKey.encoded,
                                Base64.NO_PADDING
                            )
                        )
                        encryptionProgressListener.onSaltCalculated(salt.toString())
                    }

                    encryptionMode = Cipher.ENCRYPT_MODE

                    // only execute when the key has been calculated
                    execute()
                }
            }).build()
    }

    fun decrypt(secretKey: String = "") {

        if (!secretKey.isEmpty()) {
            this.secretKey = SecretKeySpec(Base64.decode(secretKey, Base64.NO_PADDING), ALGORITHM)
        }

        encryptionMode = Cipher.DECRYPT_MODE
        execute()
    }

    fun decrypt(password: String, passwordSalt: String) {

        SecretKeyHandler.Builder()
            .withPassword(password)
            .withSalt(SecretKeySalt.getInstance(passwordSalt)) // this is mandatory
            .withKeyLength(SecretKeyHandler.KeyLength.K256)
            .onKeyGenerationComplete(object : SecretKeyHandler.KeyGenerationCompleteListener {
                override fun onKeyGenerationComplete(key: SecretKeySpec, salt: SecretKeySalt) {

                    Log.i("BQ7CH72", "decrypt key :: ${Base64.encodeToString(key.encoded, Base64.NO_PADDING)}")

                    encryptionMode = Cipher.DECRYPT_MODE
                    secretKey = key

                    // only execute when the key has been calculated
                    execute()
                }
            }).build()
    }

    companion object {

        // mode of transformation
        private val TRANSFORMATION_CBC7 = "AES/CBC/PKCS7Padding"
        private val TRANSFORMATION_CBC5 = "AES/CBC/PKCS5Padding"
        private val TRANSFORMATION_GCM = "AES/GCM/NOPADDING"

        private val BUFFER_SMALL = 1024
        private val BUFFER_MEDIUM = 4 * 1024
        private val BUFFER_LARGE = 8 * 1024

        // the encryption algorithm
        private val ALGORITHM = "AES"

        // specify the key size
        private val KEY_SIZE = 256

        // initilization vector
        val iv = "passwordpass".toByteArray()

    }

}