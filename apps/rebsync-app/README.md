# rebsync-app

A Tauri 2 shell used to check that `rebsync-core` compiles and links for Android.
It is not part of the production Cargo workspace and has no phone transport,
background sync or broad filesystem permissions yet.

```bash
npm install
export ANDROID_HOME="$HOME/.local/android-sdk"
export NDK_HOME="$HOME/.local/android-sdk/ndk/27.2.12479018"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
npm run tauri android build -- --debug --apk --target aarch64
```

The APK is written under `src-tauri/gen/android/app/build/outputs/apk/`.

## Generated Android project

`src-tauri/gen/android/` is committed so the build is reproducible. Tauri's
generated `app/build.gradle.kts` sets `rootDirRel = "../../../"`, which makes
Gradle run `npm run -- tauri …` from `src-tauri/`, where there is no npm project.
It is changed to `../../../../` so Gradle runs from this directory. Re-check that
line if `tauri android init` regenerates the project.
