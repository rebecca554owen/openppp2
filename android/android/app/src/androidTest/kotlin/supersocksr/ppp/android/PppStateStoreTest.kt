package supersocksr.ppp.android

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
class PppStateStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun reset() {
        PppStateStore.clearRuntimeSnapshot(context)
        PppStateStore.clearLastError(context)
        PppStateStore.clearLinkState(context)
    }

    @Test
    fun snapshotIsNeverObservedPartiallyWritten() {
        PppStateStore.setLinkState(context, 0)
        val pad = "x".repeat(8192)
        val payloads = (0 until 4).map { generation ->
            "{\"schema_version\":1,\"generation\":$generation," +
                "\"monotonic_ms\":0,\"phase\":\"connected\",\"pad\":\"$pad\"}"
        }

        val stop = AtomicBoolean(false)
        val partial = AtomicReference<String?>(null)
        val writers = payloads.map { payload ->
            Thread {
                while (!stop.get()) {
                    PppStateStore.setRuntimeSnapshot(context, payload)
                }
            }.also { it.start() }
        }
        val reader = Thread {
            while (!stop.get()) {
                val raw = PppStateStore.getRuntimeSnapshotIfAlive(context) ?: continue
                if (!payloads.contains(raw)) {
                    partial.set(raw)
                    return@Thread
                }
            }
        }.also { it.start() }

        SystemClock.sleep(1500L)
        stop.set(true)
        writers.forEach { it.join() }
        reader.join()

        assertNull("observed a partially written snapshot", partial.get())
    }

    @Test
    fun snapshotFromADeadSessionIsNotServed() {
        val snapshot = """{"schema_version":1,"generation":7,"monotonic_ms":10,"phase":"connected"}"""
        PppStateStore.setRuntimeSnapshot(context, snapshot)
        PppStateStore.setLinkState(context, 0)
        assertTrue(PppStateStore.isVpnAlive(context))
        assertEquals(snapshot, PppStateStore.getRuntimeSnapshotIfAlive(context))

        PppStateStore.clearLinkState(context)
        assertFalse(PppStateStore.isVpnAlive(context))
        assertNull(PppStateStore.getRuntimeSnapshotIfAlive(context))
    }

    @Test
    fun aStaleHeartbeatStopsServingTheSnapshot() {
        val snapshot = """{"schema_version":1,"generation":7,"monotonic_ms":10,"phase":"connected"}"""
        PppStateStore.setRuntimeSnapshot(context, snapshot)
        PppStateStore.setLinkState(context, 0)

        val heartbeat = File(context.filesDir, "openppp2-linkstate.txt")
        val aged = System.currentTimeMillis() - PppStateStore.HEARTBEAT_STALE_MS - 5_000L
        if (!heartbeat.setLastModified(aged)) {
            return // filesystem refused the backdate; nothing to assert here
        }

        assertFalse(PppStateStore.isVpnAlive(context))
        assertNull(PppStateStore.getRuntimeSnapshotIfAlive(context))
    }

    @Test
    fun lastErrorRoundTripsAndClears() {
        assertEquals("", PppStateStore.getLastError(context))

        PppStateStore.setLastError(context, "Failed to establish VPN interface")
        assertEquals(
            "Failed to establish VPN interface",
            PppStateStore.getLastError(context)
        )

        PppStateStore.clearLastError(context)
        assertEquals("", PppStateStore.getLastError(context))
    }

    @Test
    fun temporaryFilesDoNotSurviveWrites() {
        PppStateStore.setRuntimeSnapshot(context, "{}")
        PppStateStore.setLastError(context, "boom")
        val leftovers = context.filesDir.listFiles { file -> file.name.endsWith(".tmp") }
        assertEquals(0, leftovers?.size ?: 0)
    }
}
