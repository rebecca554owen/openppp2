package supersocksr.ppp.android

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object PppLog {
    private const val FILE_NAME = "openppp2-vpn.log"
    private const val TAG = "OpenPPP2Log"
    private val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    fun path(context: Context): String {
        return File(context.filesDir, FILE_NAME).absolutePath
    }

    fun read(context: Context): String {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) return ""
        return file.readText()
    }

    fun clear(context: Context) {
        File(context.filesDir, FILE_NAME).writeText("")
    }

    fun write(context: Context, message: String) {
        val line = "${formatter.format(Date())} $message\n"
        Log.e(TAG, message)
        File(context.filesDir, FILE_NAME).appendText(line)
    }

    fun write(context: Context, message: String, throwable: Throwable) {
        write(context, "$message\n${Log.getStackTraceString(throwable)}")
    }
}
