package com.netcontrol.app.data

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Process-wide, event-triggered writer; it creates no timer and keeps only the bounded Room history. */
object DiagnosticEventLogger {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun record(context: Context, type: String, detail: String) {
        scope.launch {
            runCatching {
                val dao = NetControlDatabase.get(context.applicationContext).eventDao()
                dao.insert(DiagnosticEventEntity(type = type, detail = detail))
                dao.trimToLimit()
            }
        }
    }
}
