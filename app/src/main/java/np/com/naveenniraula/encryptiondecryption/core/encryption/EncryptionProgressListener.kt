package np.com.naveenniraula.encryptiondecryption.core.encryption

interface EncryptionProgressListener {
    fun onStart()
    fun onKeyGenerated(key: String)
    fun onSaltCalculated(salt: String)
    fun onProgress(percentage: Long)
    fun onSuccess()
    fun onError(errorCause: String)
}