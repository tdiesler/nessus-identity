package io.nessus.identity.ebsi

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.RoutingCall
import io.ktor.server.sessions.sessions
import io.nessus.identity.ebsi.SessionsStore.getLoginContextFromSession
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import kotlinx.coroutines.runBlocking

object LoginHandler {

    val log = KotlinLogging.logger {}

    // Handle Login ----------------------------------------------------------------------------------------------------
    //
    suspend fun handleLogin(call: RoutingCall) {

        val params = call.receiveParameters()
        val email = params["email"]
        val password = params["password"]

        if (email.isNullOrBlank() || password.isNullOrBlank())
            return call.respond(HttpStatusCode.BadRequest, "Missing email or password")

        runBlocking {
            val ctx = widWalletSvc.loginWithWallet(LoginParams(LoginType.EMAIL, email, password))
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
                ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, it)
            }
            val wid = ctx.walletId
            val did = ctx.maybeDidInfo?.did
            SessionsStore.setCookieDataInSession(call, CookieData(wid, did))
            val dstId = LoginContext.getTargetId(wid, did ?: "")
            SessionsStore.putLoginContext(dstId, ctx)
        }
    }

    // Handle Logout ---------------------------------------------------------------------------------------------------
    //
    suspend fun handleLogout(call: RoutingCall) {
        val ctx = getLoginContextFromSession(call)
        if (ctx != null) {
            SessionsStore.removeLoginContext(ctx.targetId)
            ctx.close()
        }
        call.sessions.clear(CookieData.NAME)
        call.respondRedirect("/")
    }
}