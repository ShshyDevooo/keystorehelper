package com.shshy.keystorehelper

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.shshy.keystorelib.KeyStoreRSA
import java.lang.StringBuilder

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        KeyStoreRSA.getInstance().generateKey(this)
        val strBuilder = StringBuilder()
        for (i in 0 until 100)
            strBuilder.append("shishaoyang我是啊发发的+-/}{")
        val encryptedData =
            KeyStoreRSA.getInstance().encryptSpilt(strBuilder.toString().toByteArray())
        encryptedData?.let {
            val decryptedData = KeyStoreRSA.getInstance().decryptSpilt(it)
            Log.e("aaa", "${strBuilder.toString() == String(decryptedData ?: ByteArray(0))}")
        }

        val signData = KeyStoreRSA.getInstance().sign(strBuilder.toString().toByteArray())
        signData?.let {
            Log.e("aaa", String(it))
            val verify =
                KeyStoreRSA.getInstance().verify(strBuilder.toString().toByteArray(), it)
            Log.e("aaa", "$verify")
        }
    }
}
