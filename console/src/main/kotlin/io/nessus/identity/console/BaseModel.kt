package io.nessus.identity.console

import io.ktor.server.routing.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.HttpSessionStore.findLoginContext
import io.nessus.identity.types.UserRole

class BaseModel() : HashMap<String, Any>() {

    val versionInfo = getVersionInfo()
    val loginContexts = mutableMapOf<UserRole, LoginContext>()

    init {
        this["versionInfo"] = versionInfo
    }

    fun withLoginContext(call: RoutingCall, role: UserRole): BaseModel {
        val ctx = findLoginContext(call, role) ?: LoginContext().withUserRole(role)
        return withLoginContext(ctx)
    }

    fun withLoginContext(ctx: LoginContext): BaseModel {
        this["${ctx.userRole.name.lowercase()}Auth"] = ctx
        loginContexts[ctx.userRole] = ctx
        return this
    }
}