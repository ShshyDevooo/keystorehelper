package com.shshy.keystorehelper

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.shshy.keystorelib.KeyStoreRSA

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        KeyStoreRSA.getInstance().generateKey(this)
        val encryptedData =
            KeyStoreRSA.getInstance().encrypt("shishaoyang我是啊发发的+-/}{".toByteArray())
        encryptedData?.let {
            Log.e("aaa", String(it))
            val decryptedData = KeyStoreRSA.getInstance().decrypt(it)
            Log.e("aaa", String(decryptedData ?: ByteArray(0)))
        }

        val signData = KeyStoreRSA.getInstance().sign("shishaoyang我是啊发发的+-/}{".toByteArray())
        signData?.let {
            Log.e("aaa", String(it))
            val verify =
                KeyStoreRSA.getInstance().verify("shishaoyang我是啊发发的+-/}{".toByteArray(), it)
            Log.e("aaa", "$verify")
        }
    }
}
