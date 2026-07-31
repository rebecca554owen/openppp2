#pragma once

#include <ppp/stdafx.h>

#if defined(_ANDROID)

#include <jni.h>
#include <memory>

namespace ppp
{
    namespace configurations
    {
        class AppConfiguration;
    }

    namespace android
    {
        bool                                                            InitializeTelemetryBridge(JavaVM* vm, JNIEnv* env) noexcept;
        void                                                            ShutdownTelemetryBridge(JNIEnv* env = NULLPTR) noexcept;
        void                                                            InstallHttpPostSink() noexcept;
        void                                                            SetTelemetryResourceAttribute(const char* key, const char* value) noexcept;
        void                                                            ClearTelemetryResourceAttributes() noexcept;
        void                                                            ConfigureNativeTelemetry(
                                                                            const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
    }
}

#endif
