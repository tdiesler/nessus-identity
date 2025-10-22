package io.nessus.identity.console

import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.LoginParams

object SessionsStore {

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessionStore = mutableMapOf<String, LoginContext>()

    fun requireLoginContext(call: RoutingCall): LoginContext {
        val ctx = findLoginContext(call) ?: error("No LoginContext")
        return ctx
    }

    suspend fun newLoginContext(call: RoutingCall, params: LoginParams): LoginContext {
        val ctx = LoginContext.login(params).withWalletInfo()
        val wid = ctx.walletId
        val did = ctx.maybeDidInfo?.did
        setCookieDataInSession(call, CookieData(wid, did))
        sessionStore[ctx.targetId] = ctx
        return ctx
    }

    fun findLoginContext(call: RoutingCall): LoginContext? {
        val cookie = getCookieDataFromSession(call)
        val ctx = cookie?.let {
            findLoginContext(it.wid, it.did ?: "")
        }
        return ctx
    }

    fun findLoginContext(wid: String, did: String): LoginContext? {
        val targetId = LoginContext.getTargetId(wid, did)
        return sessionStore[targetId]
    }

    fun logout(call: RoutingCall) {
        findLoginContext(call)?.also { ctx ->
            call.sessions.clear(CookieData.NAME)
        }
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    private fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

}