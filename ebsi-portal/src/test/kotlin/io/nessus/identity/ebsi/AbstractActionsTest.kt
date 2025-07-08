package io.nessus.identity.ebsi

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import io.nessus.identity.waltid.User

abstract class AbstractActionsTest {

    val log = KotlinLogging.logger {}

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    fun userLogin(user: User): LoginContext {
        var ctx = sessions[user.email]
        if (ctx == null) {
            ctx = runBlocking {
                widWalletSvc.loginWallet(user.toLoginParams()).also { ctx ->
                    widWalletSvc.findDidByPrefix("did:key")?.also {
                        ctx.didInfo = it
                    }
                }
            }
            sessions[user.email] = ctx
        }
        return ctx
    }
}