package io.nessus.identity.waltid


import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import java.nio.file.Files
import java.nio.file.Paths

abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}

    fun authLogin(user: User): LoginContext {
        if (!widWalletSvc.hasLoginContext()) {
            runBlocking {
                widWalletSvc.loginWallet(user.toLoginParams()).also { ctx ->
                    widWalletSvc.findDidByPrefix("did:key")?.also {
                        ctx.didInfo = it
                    }
                }
            }
        }
        return widWalletSvc.getLoginContext()
    }

    suspend fun authLoginWithWallet (user: User): LoginContext {
        val ctx = authLogin(user)
        if (ctx.maybeWalletInfo == null) {
            ctx.walletInfo = widWalletSvc.listWallets().first()
        }
        return ctx
    }

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}