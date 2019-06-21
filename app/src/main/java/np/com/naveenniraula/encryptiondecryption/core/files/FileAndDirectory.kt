package np.com.naveenniraula.encryptiondecryption.core.files

import android.os.AsyncTask
import timber.log.Timber
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom

class FileAndDirectory {

    /**
     * Create the file at specified path.
     *
     * @param path [String] the full path where the file should be created.
     * @param rewriteExisting [Boolean] true if the file must be over written if found.
     */
    fun create(path: String, rewriteExisting: Boolean = false) {
        val newFile = File(path)

        if (!makeParentPaths(newFile)) return // file couldn't be created

        if (rewriteExisting && newFile.exists()) throw FileAlreadyExistsException(newFile) // preventing overwrite

        newFile.createNewFile() // create file normally
    }

    /**
     * Create all the required directories.
     *
     * @param file the file which requires the path to be created.
     */
    private fun makeParentPaths(file: File): Boolean {
        return file.parentFile.mkdirs()
    }

    fun createDummy(path: String) {

        AsyncTask.execute {
            val randomByteArray = ByteArray(8*4096)
            val secureRandom = SecureRandom()

            val outStream = FileOutputStream(File(path))

            for (i in 0 until 1000) {
                secureRandom.nextBytes(randomByteArray)
                outStream.write(randomByteArray)
                outStream.flush()
                Timber.d("Writing next 4096 bytes. $i")
            }

            outStream.close()
        }

    }

}