package io.nessus.identity.console

import io.ktor.server.routing.RoutingCall
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.service.LoginContext

class BaseModel(call: RoutingCall) : HashMap<String, Any>() {
    val auth = findLoginContext(call) ?: LoginContext()
    val versionInfo = getVersionInfo()
    init {
        this["auth"] = auth
        this["versionInfo"] = versionInfo
    }
}