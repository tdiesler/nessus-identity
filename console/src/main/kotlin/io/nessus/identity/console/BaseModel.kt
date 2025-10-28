package io.nessus.identity.console

import io.ktor.server.routing.*
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.UserRole

class BaseModel() : HashMap<String, Any>() {
    val versionInfo = getVersionInfo()
    init {
        this["versionInfo"] = versionInfo
    }

    fun withLoginContext(call: RoutingCall, role: UserRole, targetId: String? = null): BaseModel {
        val ctx = findLoginContext(call, role, targetId) ?: LoginContext().withUserRole(role)
        this["${role.name.lowercase()}Auth"] = ctx
        return this
    }
}