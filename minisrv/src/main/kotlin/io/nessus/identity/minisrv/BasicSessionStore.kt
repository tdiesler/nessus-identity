package io.nessus.identity.minisrv

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginContext.Companion.USER_ATTACHMENT_KEY
import io.nessus.identity.config.User
import io.nessus.identity.toLoginParams
import io.nessus.identity.types.LoginParams
import io.nessus.identity.types.UserRole

open class BasicSessionStore : SessionStore {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from targetId
    protected val loginContexts = mutableMapOf<String, LoginContext>()

    override suspend fun login(role: UserRole, user: User): LoginContext {
        val ctx = LoginContext.login(user.toLoginParams()).withUserRole(role).withWalletInfo()
        ctx.putAttachment(USER_ATTACHMENT_KEY, user)
        loginContexts[ctx.targetId] = ctx
        return ctx
    }

    override suspend fun login(role: UserRole, params: LoginParams): LoginContext {
        val ctx = LoginContext.login(params).withUserRole(role).withWalletInfo()
        loginContexts[ctx.targetId] = ctx
        return ctx
    }

    override fun findLoginContextByUser(user: User): LoginContext? {
        val ctx = loginContexts.values.firstOrNull { it.getAttachment(USER_ATTACHMENT_KEY)?.email == user.email }
        return ctx
    }

    override fun findLoginContext(targetId: String): LoginContext? {
        val ctx = loginContexts[targetId]
        return ctx
    }

    override fun requireLoginContext(targetId: String): LoginContext {
        return requireNotNull(findLoginContext(targetId)) { "No LoginContext for $targetId" }
    }

    override fun logout(targetId: String) {
        loginContexts.remove(targetId)
    }
}