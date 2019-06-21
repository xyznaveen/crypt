package np.com.naveenniraula.encryptiondecryption

import android.Manifest
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.bottomnavigation.BottomNavigationView
import np.com.naveenniraula.encryptiondecryption.core.encryption.EncryptAsync
import np.com.naveenniraula.encryptiondecryption.core.encryption.EncryptionProgressListener
import pub.devrel.easypermissions.AfterPermissionGranted
import pub.devrel.easypermissions.EasyPermissions
import timber.log.Timber
import java.math.BigInteger
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.security.auth.x500.X500Principal


class MainActivity : AppCompatActivity(), EasyPermissions.PermissionCallbacks {

    private val onNavigationItemSelectedListener = BottomNavigationView.OnNavigationItemSelectedListener { item ->
        when (item.itemId) {
            R.id.navigation_home -> {
                return@OnNavigationItemSelectedListener true
            }
            R.id.navigation_dashboard -> {
                return@OnNavigationItemSelectedListener true
            }
            R.id.navigation_notifications -> {
                return@OnNavigationItemSelectedListener true
            }
        }
        false
    }

    private val mAlias: String = "from google _ keystore."

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val navView: BottomNavigationView = findViewById(R.id.nav_view)
        navView.setOnNavigationItemSelectedListener(onNavigationItemSelectedListener)

        askPermissionAndReadFile()

    }

    @AfterPermissionGranted(ASK_READ_WRITE)
    private fun askPermissionAndReadFile() {
        val perms = arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE)
        if (EasyPermissions.hasPermissions(this, *perms)) {

            // create new dummy file
            // FileAndDirectory().createDummy("${Environment.getExternalStorageDirectory().absolutePath}/$DUMMY_FILE_NAME")

            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val parameterSpec: KeyGenParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                KeyGenParameterSpec.Builder(
                    "alias______",
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                ).run {
                    setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    build()
                }
            } else {
                TODO("VERSION.SDK_INT < M")
            }

            kpg.initialize(parameterSpec)

            val kp = kpg.generateKeyPair()

            createKeys(this)

            // encrypt file
            val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
            }
            val aliases: Enumeration<String> = ks.aliases()

            Timber.d("keys in store ==> ${aliases.toList()}")

            // encrypt()

        } else {
            EasyPermissions.requestPermissions(
                this,
                "Read / Write permission is compulsory for this app to work",
                ASK_READ_WRITE,
                *perms
            )
        }
    }

    @Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
    fun createKeys(context: Context) {
        // BEGIN_INCLUDE(create_valid_dates)
        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 25)
        //END_INCLUDE(create_valid_dates)

        // BEGIN_INCLUDE(create_keypair)
        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore.  This example uses the AndroidKeyStore.
        val kpGenerator = KeyPairGenerator
            .getInstance(
                TYPE_RSA,
                KEYSTORE_PROVIDER_ANDROID_KEYSTORE
            )
        // END_INCLUDE(create_keypair)

        // BEGIN_INCLUDE(create_spec)
        // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
        // to the KeyPairGenerator.
        val spec: AlgorithmParameterSpec

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            // Below Android M, use the KeyPairGeneratorSpec.Builder.

            spec = KeyPairGeneratorSpec.Builder(context)
                // You'll use the alias later to retrieve the key.  It's a key for the key!
                .setAlias(mAlias)
                // The subject used for the self-signed certificate of the generated pair
                .setSubject(X500Principal("CN=$mAlias"))
                // The serial number used for the self-signed certificate of the
                // generated pair.
                .setSerialNumber(BigInteger.valueOf(1337))
                // Date range of validity for the generated pair.
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()


        } else {
            // On Android M or above, use the KeyGenparameterSpec.Builder and specify permitted
            // properties  and restrictions of the key.
            spec = KeyGenParameterSpec.Builder(mAlias, KeyProperties.PURPOSE_SIGN)
                .setCertificateSubject(X500Principal("CN=$mAlias"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSerialNumber(BigInteger.valueOf(1337))
                .setCertificateNotBefore(start.time)
                .setCertificateNotAfter(end.time)
                .build()
        }

        kpGenerator.initialize(spec)

        val kp = kpGenerator.generateKeyPair()
        // END_INCLUDE(create_spec)
        Timber.d("Public Key is: " + kp.getPublic().toString())
    }

    private fun encrypt() {

        Timber.d("Encryption in progress.")

        val envPath = Environment.getExternalStorageDirectory().absolutePath

        val ea = EncryptAsync("$envPath/$DUMMY_FILE_NAME", "$envPath/dummy.enc")
        ea.setEncryptionProgressListener(object : EncryptionProgressListener {
            override fun onSaltCalculated(salt: String) {
                Timber.d("generated salt :: $salt")
            }

            override fun onKeyGenerated(key: String) {
                Timber.d("generated key :: $key")
            }

            override fun onStart() {
                Timber.d("key generation started.")
            }

            override fun onProgress(percentage: Long) {
                Timber.d("percentage complete :: $percentage")
            }

            override fun onSuccess() {
                Timber.d("successfully encrypted file")
            }

            override fun onError(errorCause: String) {
                Timber.d("this error ==> $errorCause")
            }

        })
        ea.encrypt("password", "drowssap")
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        EasyPermissions.onRequestPermissionsResult(requestCode, permissions, grantResults, this)
    }

    override fun onPermissionsDenied(requestCode: Int, perms: MutableList<String>) {

    }

    override fun onPermissionsGranted(requestCode: Int, perms: MutableList<String>) {
        askPermissionAndReadFile()
    }

    companion object {
        const val ASK_READ_WRITE = 231
        const val DUMMY_FILE_NAME = "dummy.file"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }

}
