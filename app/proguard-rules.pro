# Keep JNI entry points stable for the native bridge.
-keepclasseswithmembernames class com.netcontrol.app.network.NativeEngine {
    native <methods>;
}
