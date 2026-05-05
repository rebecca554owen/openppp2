package supersocksr.ppp.android

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject

class MainActivity : FlutterActivity() {
    companion object {
        private const val METHOD_CHANNEL = "supersocksr.ppp/vpn"
        private const val EVENT_CHANNEL = "supersocksr.ppp/vpn_events"
        private const val VPN_PERMISSION_REQUEST = 1001
        private const val NOTIFICATION_PERMISSION_REQUEST = 1002

        private var eventSink: EventChannel.EventSink? = null
        private val mainHandler = Handler(Looper.getMainLooper())

        fun sendEvent(data: Map<String, Any?>) {
            mainHandler.post {
                eventSink?.success(data)
            }
        }
    }

    private var pendingConfig: String? = null
    private var pendingVpnOptions: String? = null
    private var methodResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        requestNotificationPermissionIfNeeded()

        // Method Channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "connect" -> {
                        val args = call.arguments as? Map<*, *>
                        val config = args?.get("configJson") as? String
                        if (config == null) {
                            result.error("INVALID_ARG", "Config JSON is required", null)
                            return@setMethodCallHandler
                        }
                        val options = args["vpnOptions"] as? Map<*, *>
                        handleConnect(config, JSONObject(options ?: emptyMap<Any, Any>()).toString(), result)
                    }
                    "disconnect" -> {
                        handleDisconnect(result)
                    }
                    "readLog" -> {
                        result.success(PppLog.read(this))
                    }
                    "getLogPath" -> {
                        result.success(PppLog.path(this))
                    }
                    "clearLog" -> {
                        PppLog.clear(this)
                        result.success(true)
                    }
                    "getStatistics" -> {
                        result.success(PppStateStore.getStatistics(this))
                    }
                    "requestPermission" -> {
                        requestVpnPermission(result)
                    }
                    "getState" -> {
                        val log = PppLog.read(this)
                        val connectedAt = maxOf(
                            log.lastIndexOf("VPN started with key"),
                            log.lastIndexOf("onStarted key=")
                        )
                        val connectingAt = maxOf(
                            log.lastIndexOf("set_network_interface result=0"),
                            log.lastIndexOf("before libopenppp2.run"),
                            log.lastIndexOf("builder.establish result=true"),
                            log.lastIndexOf("startForeground done")
                        )
                        val stoppedAt = maxOf(
                            log.lastIndexOf("stopVpn requested"),
                            log.lastIndexOf("libopenppp2.run returned"),
                            log.lastIndexOf("failed"),
                            log.lastIndexOf("exception"),
                            log.lastIndexOf("error:")
                        )
                        val state = when {
                            connectedAt > stoppedAt -> 2
                            connectingAt > stoppedAt -> 1
                            else -> 0
                        }
                        if (state == 2) {
                            PppStateStore.set(this, 2)
                            result.success(2)
                            return@setMethodCallHandler
                        }
                        val persistedState = PppStateStore.get(this)
                        if (persistedState == 1 || persistedState == 2) {
                            result.success(persistedState)
                            return@setMethodCallHandler
                        }
                        if (PppVpnService.isRunning || PppVpnService.currentState != 0) {
                            result.success(PppVpnService.currentState)
                            return@setMethodCallHandler
                        }
                        result.success(state)
                    }
                    else -> result.notImplemented()
                }
            }

        // Event Channel
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    eventSink = events
                }

                override fun onCancel(arguments: Any?) {
                    eventSink = null
                }
            })
    }

    private fun handleConnect(config: String, vpnOptions: String, result: MethodChannel.Result) {
        try {
            PppLog.write(this, "connect requested")
            PppStateStore.set(this, 1)
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // Need to request VPN permission first
                pendingConfig = config
                pendingVpnOptions = vpnOptions
                methodResult = result
                startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
            } else {
                // Permission already granted, start VPN
                startVpnService(config, vpnOptions)
                result.success(true)
            }
        } catch (e: Throwable) {
            PppStateStore.set(this, 0)
            PppLog.write(this, "handleConnect failed", e)
            result.error("CONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
        }
    }

    private fun handleDisconnect(result: MethodChannel.Result) {
        PppStateStore.set(this, 0)
        val intent = Intent(this, PppVpnService::class.java).apply {
            action = PppVpnService.ACTION_DISCONNECT
        }
        try {
            startService(intent)
            result.success(true)
        } catch (e: Throwable) {
            PppStateStore.set(this, PppVpnService.currentState)
            PppLog.write(this, "disconnect failed", e)
            result.error("DISCONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_PERMISSION_REQUEST
            )
        }
    }

    private fun requestVpnPermission(result: MethodChannel.Result) {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            methodResult = result
            startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
        } else {
            result.success(true) // Already granted
        }
    }

    private fun startVpnService(config: String, vpnOptions: String) {
        val intent = Intent(this, PppVpnService::class.java).apply {
            action = PppVpnService.ACTION_CONNECT
            putExtra(PppVpnService.EXTRA_CONFIG, config)
            putExtra(PppVpnService.EXTRA_VPN_OPTIONS, vpnOptions)
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Throwable) {
            PppLog.write(this, "startVpnService failed", e)
            throw e
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION_REQUEST) {
            if (resultCode == Activity.RESULT_OK) {
                val config = pendingConfig
                if (config != null) {
                    try {
                        startVpnService(config, pendingVpnOptions ?: "{}")
                        methodResult?.success(true)
                    } catch (e: Throwable) {
                        PppLog.write(this, "startVpnService after permission failed", e)
                        methodResult?.error("CONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
                    }
                } else {
                    methodResult?.success(true) // Permission granted
                }
            } else {
                methodResult?.error("PERMISSION_DENIED", "VPN permission denied by user", null)
            }
            pendingConfig = null
            pendingVpnOptions = null
            methodResult = null
        }
    }
}
