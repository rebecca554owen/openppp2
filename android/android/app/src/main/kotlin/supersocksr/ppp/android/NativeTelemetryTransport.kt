package supersocksr.ppp.android

import android.content.Context
import android.util.Log
import supersocksr.ppp.android.c.libopenppp2
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Bounded-queue OTLP HTTP transport for native C++ telemetry.
 * Mirrors iOS [NativeTelemetryTransport].
 */
object NativeTelemetryTransport {
    private const val TAG = "OpenPPP2Telemetry"
    private const val MAX_PENDING_POSTS = 16

    @Volatile
    private var installed = false

    private val lock = Any()
    private val pendingPosts = LinkedBlockingDeque<Pair<String, ByteArray>>()
    private val workerScheduled = AtomicBoolean(false)
    private val droppedPosts = AtomicInteger(0)

    fun install(context: Context) {
        if (installed) return
        installed = true

        libopenppp2.installNativeTelemetryHttpPost()
        libopenppp2.clearNativeTelemetryResourceAttributes()
        for ((key, value) in TelemetryIdentity.nativeResourceAttributes(context)) {
            libopenppp2.setNativeTelemetryResourceAttribute(key, value)
        }
    }

    /**
     * Called from JNI on the native dataplane thread; must not block.
     */
    @JvmStatic
    fun enqueuePost(url: String, body: ByteArray): Boolean {
        if (url.isBlank() || body.isEmpty()) return false

        synchronized(lock) {
            if (pendingPosts.size >= MAX_PENDING_POSTS) {
                val dropped = droppedPosts.incrementAndGet()
                if (dropped == 1 || dropped % 32 == 0) {
                    Log.w(TAG, "native telemetry queue full; dropped=$dropped")
                }
                return false
            }
            pendingPosts.addLast(url to body)
            if (workerScheduled.compareAndSet(false, true)) {
                Thread(::drainPendingPosts, "openppp2-native-telemetry").start()
            }
        }
        return true
    }

    private fun drainPendingPosts() {
        try {
            while (true) {
                val item = synchronized(lock) {
                    pendingPosts.pollFirst()
                } ?: break
                performPost(item.first, item.second)
            }
        } finally {
            workerScheduled.set(false)
            synchronized(lock) {
                if (pendingPosts.isNotEmpty() &&
                    workerScheduled.compareAndSet(false, true)
                ) {
                    Thread(::drainPendingPosts, "openppp2-native-telemetry").start()
                }
            }
        }
    }

    private fun performPost(url: String, body: ByteArray): Boolean {
        return try {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 3000
                readTimeout = 4000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }
            connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            val ok = code in 200..299
            if (!ok) {
                Log.w(TAG, "native telemetry upload rejected: HTTP $code")
            }
            connection.disconnect()
            ok
        } catch (e: Exception) {
            Log.w(TAG, "native telemetry upload failed: ${e.message}")
            false
        }
    }
}
