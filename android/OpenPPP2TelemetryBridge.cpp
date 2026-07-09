#include <ppp/stdafx.h>

#if defined(_ANDROID)

#include "OpenPPP2TelemetryBridge.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Telemetry.h>

#include <android/log.h>

namespace ppp
{
    namespace android
    {
        namespace
        {
            constexpr const char* TAG = "OpenPPP2Telemetry";

            class TelemetryBridgeState final
            {
            public:
                JavaVM*                                             vm = NULLPTR;
                jclass                                              clazz = NULLPTR;
                jmethodID                                           http_post = NULLPTR;
                bool                                                http_post_installed = false;
                std::once_flag                                      console_sink_once;
                std::mutex                                          syncobj;
            };

            TelemetryBridgeState& GetState() noexcept
            {
                static TelemetryBridgeState state;
                return state;
            }

            void TelemetryConsoleSink(const char* line) noexcept
            {
                if (NULLPTR == line)
                {
                    return;
                }

                __android_log_print(ANDROID_LOG_INFO, TAG, "%s", line);
            }

            bool ClearException(JNIEnv* env, const char* where) noexcept
            {
                if (NULLPTR == env || !env->ExceptionCheck())
                {
                    return false;
                }

                __android_log_print(ANDROID_LOG_WARN, TAG, "jni exception in %s", NULLPTR != where ? where : "unknown");
                env->ExceptionClear();
                return true;
            }

            JNIEnv* AttachEnvironment(JavaVM* vm, bool& attached) noexcept
            {
                attached = false;
                if (NULLPTR == vm)
                {
                    return NULLPTR;
                }

                JNIEnv* env = NULLPTR;
                jint result = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
                if (JNI_OK == result)
                {
                    return env;
                }

                if (JNI_EDETACHED != result)
                {
                    return NULLPTR;
                }

#if defined(__ANDROID__)
                if (JNI_OK != vm->AttachCurrentThread(&env, NULLPTR))
#else
                if (JNI_OK != vm->AttachCurrentThread(reinterpret_cast<void**>(&env), NULLPTR))
#endif
                {
                    return NULLPTR;
                }

                attached = true;
                return env;
            }

            bool CacheHttpPostClassLocked(TelemetryBridgeState& state, JNIEnv* env) noexcept
            {
                if (NULLPTR == env)
                {
                    return false;
                }

                if (NULLPTR != state.clazz && NULLPTR != state.http_post)
                {
                    return true;
                }

                jclass local_clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
                ClearException(env, "FindClass(" LIBOPENPPP2_CLASSNAME ")");
                if (NULLPTR == local_clazz)
                {
                    __android_log_print(ANDROID_LOG_WARN, TAG, "class not found: %s", LIBOPENPPP2_CLASSNAME);
                    return false;
                }

                jmethodID method = env->GetStaticMethodID(
                    local_clazz,
                    "telemetryHttpPost",
                    "(Ljava/lang/String;[B)Z");
                ClearException(env, "GetStaticMethodID(telemetryHttpPost)");
                if (NULLPTR == method)
                {
                    env->DeleteLocalRef(local_clazz);
                    __android_log_print(ANDROID_LOG_WARN, TAG, "method not found: telemetryHttpPost(String,[B)Z");
                    return false;
                }

                jclass global_clazz = static_cast<jclass>(env->NewGlobalRef(local_clazz));
                env->DeleteLocalRef(local_clazz);
                ClearException(env, "NewGlobalRef(telemetry class)");
                if (NULLPTR == global_clazz)
                {
                    return false;
                }

                if (NULLPTR != state.clazz)
                {
                    env->DeleteGlobalRef(state.clazz);
                }

                state.clazz = global_clazz;
                state.http_post = method;
                return true;
            }

            bool AndroidHttpPostSink(const char* url, const void* body, size_t body_len, void* user_data) noexcept
            {
                (void)user_data;
                if (NULLPTR == url || NULLPTR == body || 0 == body_len)
                {
                    return false;
                }

                JavaVM* vm = NULLPTR;
                jclass clazz = NULLPTR;
                jmethodID method = NULLPTR;
                {
                    TelemetryBridgeState& state = GetState();
                    std::lock_guard<std::mutex> scope(state.syncobj);
                    vm = state.vm;
                    clazz = state.clazz;
                    method = state.http_post;
                }

                bool attached = false;
                JNIEnv* env = AttachEnvironment(vm, attached);
                if (NULLPTR == env)
                {
                    return false;
                }

                if (NULLPTR == clazz || NULLPTR == method)
                {
                    TelemetryBridgeState& state = GetState();
                    std::lock_guard<std::mutex> scope(state.syncobj);
                    if (!CacheHttpPostClassLocked(state, env))
                    {
                        if (attached)
                        {
                            vm->DetachCurrentThread();
                        }
                        return false;
                    }

                    clazz = state.clazz;
                    method = state.http_post;
                }

                jstring jurl = env->NewStringUTF(url);
                if (NULLPTR == jurl)
                {
                    if (attached)
                    {
                        vm->DetachCurrentThread();
                    }
                    return false;
                }

                jbyteArray jbody = env->NewByteArray(static_cast<jsize>(body_len));
                if (NULLPTR == jbody)
                {
                    env->DeleteLocalRef(jurl);
                    if (attached)
                    {
                        vm->DetachCurrentThread();
                    }
                    return false;
                }

                env->SetByteArrayRegion(
                    jbody,
                    0,
                    static_cast<jsize>(body_len),
                    static_cast<const jbyte*>(body));

                jboolean result = env->CallStaticBooleanMethod(clazz, method, jurl, jbody);
                if (ClearException(env, "CallStaticBooleanMethod(telemetryHttpPost)"))
                {
                    result = JNI_FALSE;
                }

                env->DeleteLocalRef(jurl);
                env->DeleteLocalRef(jbody);

                if (attached)
                {
                    vm->DetachCurrentThread();
                }

                return result == JNI_TRUE;
            }
        }

        bool InitializeTelemetryBridge(JavaVM* vm, JNIEnv* env) noexcept
        {
            if (NULLPTR == vm || NULLPTR == env)
            {
                return false;
            }

            TelemetryBridgeState& state = GetState();
            {
                std::lock_guard<std::mutex> scope(state.syncobj);
                state.vm = vm;
            }

            std::call_once(state.console_sink_once, []() noexcept {
                ppp::telemetry::SetConsoleSink(TelemetryConsoleSink);
            });

            return CacheHttpPostClassLocked(state, env);
        }

        void ShutdownTelemetryBridge(JNIEnv* env) noexcept
        {
            TelemetryBridgeState& state = GetState();
            JavaVM* vm = NULLPTR;
            jclass clazz = NULLPTR;

            {
                std::lock_guard<std::mutex> scope(state.syncobj);
                vm = state.vm;
                clazz = state.clazz;
                state.clazz = NULLPTR;
                state.http_post = NULLPTR;
                state.vm = NULLPTR;
                state.http_post_installed = false;
            }

            ppp::telemetry::SetHttpPostSink(nullptr, nullptr);

            if (NULLPTR == clazz)
            {
                return;
            }

            bool attached = false;
            JNIEnv* release_env = env;
            if (NULLPTR == release_env)
            {
                release_env = AttachEnvironment(vm, attached);
            }

            if (NULLPTR != release_env)
            {
                release_env->DeleteGlobalRef(clazz);
            }

            if (attached && NULLPTR != vm)
            {
                vm->DetachCurrentThread();
            }
        }

        void InstallHttpPostSink() noexcept
        {
            TelemetryBridgeState& state = GetState();
            std::lock_guard<std::mutex> scope(state.syncobj);
            if (!state.http_post_installed)
            {
                ppp::telemetry::SetHttpPostSink(AndroidHttpPostSink, nullptr);
                state.http_post_installed = true;
            }
        }

        void SetTelemetryResourceAttribute(const char* key, const char* value) noexcept
        {
            ppp::telemetry::SetResourceAttribute(key, value);
        }

        void ClearTelemetryResourceAttributes() noexcept
        {
            ppp::telemetry::ClearResourceAttributes();
        }

        void ConfigureNativeTelemetry(
            const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
        {
            if (NULLPTR == configuration)
            {
                return;
            }

            ppp::telemetry::SetEnabled(configuration->telemetry.enabled);
            ppp::telemetry::SetMinLevel(configuration->telemetry.level);
            ppp::telemetry::SetCountEnabled(configuration->telemetry.count);
            ppp::telemetry::SetSpanEnabled(configuration->telemetry.span);
            ppp::telemetry::SetConsoleLogEnabled(configuration->telemetry.console_log);
            ppp::telemetry::SetConsoleMetricEnabled(configuration->telemetry.console_metric);
            ppp::telemetry::SetConsoleSpanEnabled(configuration->telemetry.console_span);
            ppp::telemetry::Configure(configuration->telemetry.endpoint.c_str());
            ppp::telemetry::SetLogFile(configuration->telemetry.log_file.c_str());

            __android_log_print(
                ANDROID_LOG_INFO,
                TAG,
                "configured enabled=%d level=%d count=%d span=%d endpoint=%s",
                configuration->telemetry.enabled ? 1 : 0,
                configuration->telemetry.level,
                configuration->telemetry.count ? 1 : 0,
                configuration->telemetry.span ? 1 : 0,
                configuration->telemetry.endpoint.empty()
                    ? "(empty)"
                    : configuration->telemetry.endpoint.c_str());
        }
    }
}

#endif
