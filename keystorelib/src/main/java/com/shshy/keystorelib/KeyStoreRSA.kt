package com.shshy.keystorelib

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.TextUtils
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal


/**
 * @author  ShiShY
 * @Description:
 * @data  2020/2/19 15:09
 */
class KeyStoreRSA private constructor() {
    companion object {
        private val lock = Any()
        private var _instance: KeyStoreRSA? = null
        fun getInstance(): KeyStoreRSA {
            if (_instance == null) {
                synchronized(lock) {
                    if (_instance == null) {
                        _instance = KeyStoreRSA()
                    }
                }
            }
            return _instance!!
        }
    }

    private var keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    private var x500Principal: X500Principal
    private val CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    private val defaultAlias = "shshydev"
    private val DEFAULT_KEY_SIZE = 2048
    private val DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11
    private val DEFAULT_SPLIT = "#AAAAAAAA#".toByteArray()

    init {
        keyStore.load(null)
        x500Principal = X500Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")
    }

    fun getAliases(): Enumeration<String>? {
        return keyStore.aliases()
    }

    fun containsAlias(alias: String): Boolean {
        if (TextUtils.isEmpty(alias))
            return false
        return keyStore.containsAlias(alias)
    }

    fun deleteKey(alias: String) {
        keyStore.deleteEntry(alias)
    }

    fun generateKey(context: Context, alias: String = defaultAlias): KeyPair? {
        if (containsAlias(alias))
            return null
        try {
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 100)
            val spec =
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    KeyPairGeneratorSpec.Builder(context.applicationContext)
                        .setAlias(alias)
                        .setSubject(x500Principal)
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build()
                } else {
                    KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setKeySize(DEFAULT_KEY_SIZE)
                        .setUserAuthenticationRequired(false)
                        .setCertificateSubject(x500Principal)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                        .setCertificateNotBefore(start.time)
                        .setCertificateNotAfter(end.time)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build()
                }
            val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
            generator.initialize(spec)
            return generator.generateKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun encrypt(data: ByteArray, alias: String = defaultAlias): ByteArray? {
        return try {
            val publicKey = getPublicKey(alias)
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            cipher.doFinal(data)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun decrypt(data: ByteArray, alias: String = defaultAlias): ByteArray? {
        return try {
            val privateKey = getPrivateKey(alias)
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher.doFinal(data)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun sign(data: ByteArray, alias: String = defaultAlias): ByteArray? {
        return try {
            val signature = Signature.getInstance("SHA1withRSA")
            signature.initSign(getPrivateKey(alias))
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun verify(data: ByteArray, signatureData: ByteArray, alias: String = defaultAlias): Boolean {
        return try {
            val signature = Signature.getInstance("SHA1withRSA")
            signature.initVerify(getPublicKey(alias))
            signature.update(data)
            signature.verify(signatureData)
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    fun encryptSpilt(data: ByteArray, alias: String = defaultAlias): ByteArray? {
        return try {
            val dataLen = data.size
            if (dataLen <= DEFAULT_BUFFERSIZE) {
                return encrypt(data, alias)
            }
            val allBytes = ArrayList<Byte>(2048)
            var bufIndex = 0
            var subDataLoop = 0
            var buf: ByteArray? = ByteArray(DEFAULT_BUFFERSIZE)
            for (i in 0 until dataLen) {
                buf?.let {
                    it[bufIndex] = data[i]
                    if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                        subDataLoop++
                        if (subDataLoop != 1) {
                            for (b in DEFAULT_SPLIT) {
                                allBytes.add(b)
                            }
                        }
                        var encryptBytes = encrypt(it, alias)
                        encryptBytes?.let {
                            for (b in encryptBytes) {
                                allBytes.add(b)
                            }
                        }
                        bufIndex = 0
                        buf = if (i == dataLen - 1) {
                            null
                        } else {
                            ByteArray(DEFAULT_BUFFERSIZE.coerceAtMost(dataLen - i - 1))
                        }
                    }
                }
            }
            val bytes = ByteArray(allBytes.size)
            allBytes.forEachIndexed { index, byte ->
                bytes[index] = byte
            }
            bytes
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 使用私钥分段解密
     */
    fun decryptSpilt(encrypted: ByteArray, alias: String = defaultAlias): ByteArray? {
        return try {
            val splitLen = DEFAULT_SPLIT.size
            if (splitLen <= 0) {
                return decrypt(encrypted, alias)
            }
            val dataLen = encrypted.size
            val allBytes = ArrayList<Byte>(1024)
            var latestStartIndex = 0
            var i = 0
            while (i < dataLen) {
                val bt = encrypted[i]
                var isMatchSplit = false
                if (i == dataLen - 1) {
                    // 到data的最后了
                    val part = ByteArray(dataLen - latestStartIndex)
                    System.arraycopy(encrypted, latestStartIndex, part, 0, part.size)
                    val decryptPart = decrypt(part, alias)
                    decryptPart?.let {
                        for (b in it) {
                            allBytes.add(b)
                        }
                    }
                    latestStartIndex = i + splitLen
                    i = latestStartIndex - 1
                } else if (bt == DEFAULT_SPLIT[0]) {
                    // 这个是以split[0]开头
                    if (splitLen > 1) {
                        if (i + splitLen < dataLen) {
                            // 没有超出data的范围
                            for (j in 1 until splitLen) {
                                if (DEFAULT_SPLIT[j] !== encrypted[i + j]) {
                                    break
                                }
                                if (j == splitLen - 1) {
                                    // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                    isMatchSplit = true
                                }
                            }
                        }
                    } else {
                        // split只有一位，则已经匹配了
                        isMatchSplit = true
                    }
                }
                if (isMatchSplit) {
                    val part = ByteArray(i - latestStartIndex)
                    System.arraycopy(encrypted, latestStartIndex, part, 0, part.size)
                    val decryptPart = decrypt(part, alias)
                    decryptPart?.let {
                        for (b in it) {
                            allBytes.add(b)
                        }
                    }
                    latestStartIndex = i + splitLen
                    i = latestStartIndex - 1
                }
                i++
            }

            val bytes = ByteArray(allBytes.size)
            allBytes.forEachIndexed { index, byte ->
                bytes[index] = byte
            }
            bytes
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun getPublicKey(alias: String): PublicKey? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyStore.getCertificate(alias).publicKey
        } else {
            val asymmetricKey = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            asymmetricKey.certificate.publicKey
        }
    }

    private fun getPrivateKey(alias: String): PrivateKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyStore.getKey(alias, null) as PrivateKey
        } else {
            val asymmetricKey = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            asymmetricKey.privateKey
        }
    }
}