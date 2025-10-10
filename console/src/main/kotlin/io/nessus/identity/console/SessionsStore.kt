package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.User

object SessionsStore {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessions = mutableMapOf<String, LoginContext>()

    suspend fun findOrCreateLoginContext(call: RoutingCall, user: User): LoginContext {
        var ctx = getCookieDataFromSession(call)?.let {
            findLoginContext(it.wid, it.did ?: "")
        }
        if (ctx == null || ctx.walletInfo.name != user.name) {
            ctx = LoginContext.login(user).withWalletInfo()
            val wid = ctx.walletId
            val did = ctx.maybeDidInfo?.did
            setCookieDataInSession(call, CookieData(wid, did))
            sessions[ctx.targetId] = ctx
        }
        return ctx
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    fun findLoginContext(wid: String, did: String): LoginContext? {
        val targetId = LoginContext.getTargetId(wid, did)
        return sessions[targetId]
    }

    private fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    private fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

}