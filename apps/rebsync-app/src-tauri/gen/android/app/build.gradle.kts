import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Release signing, never committed: REBEKAH_KEYSTORE_PROPERTIES names a
// properties file (storeFile, storePassword, keyAlias, keyPassword), else
// ./keystore.properties (gitignored), else REBEKAH_STORE_FILE and friends in
// the environment for CI. Without any of them the release APK is unsigned.
val releaseSigning = Properties().apply {
    val named = System.getenv("REBEKAH_KEYSTORE_PROPERTIES")?.let { file(it) }
    val local = rootProject.file("keystore.properties")
    when {
        named != null && named.exists() -> named.inputStream().use { load(it) }
        local.exists() -> local.inputStream().use { load(it) }
        System.getenv("REBEKAH_STORE_FILE") != null -> {
            setProperty("storeFile", System.getenv("REBEKAH_STORE_FILE"))
            setProperty("storePassword", System.getenv("REBEKAH_STORE_PASSWORD") ?: "")
            setProperty("keyAlias", System.getenv("REBEKAH_KEY_ALIAS") ?: "rebekah")
            setProperty("keyPassword", System.getenv("REBEKAH_KEY_PASSWORD") ?: "")
        }
    }
}

android {
    compileSdk = 37
    if (releaseSigning.getProperty("storeFile") != null) {
        signingConfigs {
            create("release") {
                storeFile = file(releaseSigning.getProperty("storeFile"))
                storePassword = releaseSigning.getProperty("storePassword")
                keyAlias = releaseSigning.getProperty("keyAlias")
                keyPassword = releaseSigning.getProperty("keyPassword")
            }
        }
    }
    namespace = "com.tabenius.rebsync"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "com.tabenius.rebsync"
        minSdk = 24
        targetSdk = 37
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            signingConfigs.findByName("release")?.let { signingConfig = it }
            optimization {
               enable = true
            }
            proguardFiles(
                *fileTree(".") {
                  include("**/*.pro")
                  exclude("build/**")
                }.files.toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    buildFeatures {
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

rust {
    // Gradle runs `npm run -- tauri android android-studio-script` from this
    // directory. The npm project lives at the Tauri app root, one level above
    // src-tauri; point the generated task there rather than at src-tauri.
    rootDirRel = "../../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = file("tauri.build.gradle.kts"))
