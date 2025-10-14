package io.nessus.identity.ebsi

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService

object SessionsStore {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessions = mutableMapOf<String, LoginContext>()

    fun findLoginContext(subjectId: String): LoginContext? {
        return sessions[subjectId]
    }

    fun findLoginContext(walletId: String, did: String): LoginContext? {
        val subjectId = LoginContext.Companion.getTargetId(walletId, did)
        return findLoginContext(subjectId)
    }

    fun getLoginContextFromSession(call: RoutingCall): LoginContext? {
        val dat = getCookieDataFromSession(call)
        val ctx = dat?.let { findLoginContext(it.wid, it.did ?: "") }
        return ctx
    }

    fun putLoginContext(dstId: String, ctx: LoginContext) {
        sessions[dstId] = ctx
    }

    fun removeLoginContext(dstId: String) {
        sessions.remove(dstId)
    }

    suspend fun requireLoginContext(dstId: String): LoginContext {

        // We expect the user to have logged in previously and have a valid Did
        //
        var ctx = findLoginContext(dstId)

        // Fallback
        if (ctx == null) {
            val cfg = ConfigProvider.requireEbsiConfig()
            val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail!!, cfg.userPassword!!)
            ctx = widWalletService.loginWithWallet(loginParams)
            val subjectId = LoginContext.getTargetId(ctx.walletId, "")
            sessions[subjectId] = ctx
        }

        if (ctx.maybeDidInfo == null) {
            val didInfo = widWalletService.findDidByPrefix(ctx, "did:key")
                ?: throw IllegalStateException("Cannot find required did in wallet")
            ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, didInfo)
        }

        return ctx
    }

    // Session Data ----------------------------------------------------------------------------------------------------

    fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

}