package com.tabenius.rebsync

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Environment
import android.os.storage.StorageManager
import android.system.Os
import androidx.activity.enableEdgeToEdge
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Hosts the Rebekah web UI. Before the Rust side starts, it tells the native
 * code where private files live and which volumes (internal, SD card, USB
 * drive) this app may write to, and keeps that list current as media is
 * mounted and removed.
 */
class MainActivity : TauriActivity() {
  private val mediaReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
      publishVolumes()
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    installSplashScreen()
    enableEdgeToEdge()
    Os.setenv("REBSYNC_FILES_DIR", filesDir.absolutePath, true)
    publishVolumes()
    super.onCreate(savedInstanceState)
    val filter = IntentFilter().apply {
      addAction(Intent.ACTION_MEDIA_MOUNTED)
      addAction(Intent.ACTION_MEDIA_UNMOUNTED)
      addAction(Intent.ACTION_MEDIA_REMOVED)
      addAction(Intent.ACTION_MEDIA_EJECT)
      addAction(Intent.ACTION_MEDIA_BAD_REMOVAL)
      addDataScheme("file")
    }
    // Media broadcasts come from the system, so the receiver must be exported.
    ContextCompat.registerReceiver(this, mediaReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
  }

  override fun onResume() {
    super.onResume()
    publishVolumes()
  }

  override fun onDestroy() {
    runCatching { unregisterReceiver(mediaReceiver) }
    super.onDestroy()
  }

  private fun publishVolumes() {
    runCatching {
      val storage = getSystemService(StorageManager::class.java)
      val volumes = JSONArray()
      // Also creates the app folder on each mounted volume.
      for (dir in getExternalFilesDirs(null)) {
        if (dir == null) continue
        val volume = storage?.getStorageVolume(dir)
        volumes.put(JSONObject().apply {
          put("path", dir.absolutePath)
          put("removable", volume?.isRemovable ?: false)
          put("emulated", volume?.isEmulated ?: false)
          put("primary", volume?.isPrimary ?: false)
          put("state", Environment.getExternalStorageState(dir))
          put("description", volume?.getDescription(this@MainActivity) ?: "")
          put("uuid", volume?.uuid ?: JSONObject.NULL)
        })
      }
      val target = File(filesDir, "volumes.json")
      val temp = File(filesDir, "volumes.json.tmp")
      temp.writeText(volumes.toString())
      temp.renameTo(target)
      Os.setenv("REBSYNC_VOLUMES_FILE", target.absolutePath, true)
    }
  }
}
