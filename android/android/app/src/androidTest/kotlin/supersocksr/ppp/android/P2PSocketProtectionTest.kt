package supersocksr.ppp.android

import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import supersocksr.ppp.android.c.libopenppp2
import java.net.DatagramSocket

@RunWith(AndroidJUnit4::class)
class P2PSocketProtectionTest {
    @Test
    fun testNativeBridgeProtectsRealUdpSocketWhileServiceIsActive() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val service = Intent(context, PppVpnService::class.java)
        context.stopService(service)
        waitUntil { !libopenppp2.isProtectReady() }
        libopenppp2.set_protect_enabled(true)

        DatagramSocket().use { socket ->
            ParcelFileDescriptor.fromDatagramSocket(socket).use { descriptor ->
                val fd = descriptor.fd
                assertFalse(libopenppp2.protect_socket_fd(fd))

                assertNotNull(context.startService(service))
                waitUntil { libopenppp2.isProtectReady() }
                assertTrue(libopenppp2.protect_socket_fd(fd))

                assertTrue(context.stopService(service))
                waitUntil { !libopenppp2.isProtectReady() }
                assertFalse(libopenppp2.isProtectReady())
            }
        }
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 5_000L
        while (!condition() && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(25L)
        }
        assertTrue("condition timed out", condition())
    }
}
