package com.netcontrol.app.root

import android.os.Build
import java.io.File

/**
 * Non-invasive hints only. Presence of a su binary or test-keys is not proof that root access
 * is granted. This probe never executes su or a shell command.
 */
object RootCapabilityProbe {
    data class Report(
        val backendImplemented: Boolean,
        val possibleIndicators: List<String>,
        val detail: String,
    )

    fun inspect(): Report {
        val indicators = mutableListOf<String>()
        if (Build.TAGS?.contains("test-keys", ignoreCase = true) == true) {
            indicators += "Build tags include test-keys (not proof of root)"
        }
        val candidatePaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system_ext/bin/su")
        candidatePaths.filter { path -> runCatching { File(path).canExecute() }.getOrDefault(false) }
            .forEach { path -> indicators += "Executable candidate at $path (not proof of usable root)" }
        return Report(
            backendImplemented = UnavailableRootBackend.isImplemented,
            possibleIndicators = indicators,
            detail = if (UnavailableRootBackend.isImplemented) "Root backend implemented" else
                "Root backend unavailable; no su process or arbitrary shell command is executed",
        )
    }
}
