
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

// Pin the native TCP/UDP tun2socks transport. The first build downloads the official,
// self-contained Android AAR; later builds use the cached file in app/libs.
val hevTunnelVersion = "2.19.1"
val hevTunnelAar = layout.projectDirectory.file("libs/hev-socks5-tunnel.aar").asFile
val hevTunnelAarUrl = "https://github.com/heiher/hev-socks5-tunnel/releases/download/$hevTunnelVersion/hev-socks5-tunnel.aar"

fun isValidHevAar(file: File): Boolean = runCatching {
    ZipFile(file).use { archive ->
        val classesEntry = archive.getEntry("classes.jar")
        val hasJniBinding = classesEntry != null && archive.getInputStream(classesEntry).use { stream ->
            ZipInputStream(stream).use { jar ->
                generateSequence { jar.nextEntry }.any { it.name == "hev/htproxy/TProxyService.class" }
            }
        }
        hasJniBinding &&
                archive.getEntry("jni/arm64-v8a/libhev-socks5-tunnel.so") != null &&
                archive.getEntry("jni/armeabi-v7a/libhev-socks5-tunnel.so") != null &&
                archive.getEntry("jni/x86_64/libhev-socks5-tunnel.so") != null
    }
}.getOrDefault(false)

val downloadHevTunnelAar by tasks.registering {
    outputs.file(hevTunnelAar)
    outputs.upToDateWhen { isValidHevAar(hevTunnelAar) }
    doLast {
        if (isValidHevAar(hevTunnelAar)) return@doLast
        hevTunnelAar.parentFile.mkdirs()
        val temporary = File(hevTunnelAar.parentFile, "hev-socks5-tunnel.aar.download")
        temporary.delete()
        try {
            val connection = URI(hevTunnelAarUrl).toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 60_000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "NetControl-Android-Build")
            connection.connect()
            if (connection.responseCode !in 200..299) {
                throw GradleException("HTTP ${connection.responseCode} while downloading hev-socks5-tunnel AAR")
            }
            connection.inputStream.use { input: InputStream ->
                temporary.outputStream().buffered().use { output: OutputStream ->
                    input.copyTo(output)
                }
            }
            connection.disconnect()
            if (!isValidHevAar(temporary)) {
                throw GradleException("Downloaded AAR is invalid or does not contain required Android ABIs")
            }
            if (hevTunnelAar.exists() && !hevTunnelAar.delete()) {
                throw GradleException("Could not replace existing invalid file: $hevTunnelAar")
            }
            if (!temporary.renameTo(hevTunnelAar)) {
                temporary.copyTo(hevTunnelAar, overwrite = true)
                temporary.delete()
            }
            logger.lifecycle("Using hev-socks5-tunnel $hevTunnelVersion (official Android AAR).")
        } catch (failure: Exception) {
            temporary.delete()
            throw GradleException(
                "Could not obtain hev-socks5-tunnel $hevTunnelVersion. Check internet access or place the official " +
                        "hev-socks5-tunnel.aar in app/libs. Download URL: $hevTunnelAarUrl",
                failure,
            )
        }
    }
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(downloadHevTunnelAar)
}

android {
    namespace = "com.netcontrol.app"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.netcontrol.app"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-fstack-protector-strong")
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64", "armeabi-v7a")
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isDebuggable = true
        }
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    externalNativeBuild {
        cmake {
            path = file("../native/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    packaging {
        jniLibs.useLegacyPackaging = false
        resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    implementation(files(hevTunnelAar))
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
