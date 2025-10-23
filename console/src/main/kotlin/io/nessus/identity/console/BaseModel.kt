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

    fun withRoleAuth(call: RoutingCall, role: UserRole): BaseModel {
        val auth = findLoginContext(call, role) ?: LoginContext().withUserRole(role)
        this["${role.name.lowercase()}Auth"] = auth
        return this
    }
}