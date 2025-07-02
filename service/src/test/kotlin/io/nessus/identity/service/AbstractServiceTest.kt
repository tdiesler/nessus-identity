package io.nessus.identity.service


import io.github.oshai.kotlinlogging.KotlinLogging
import java.nio.file.Files
import java.nio.file.Paths

abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}

    val walletService = ServiceProvider.walletService

    suspend fun authLogin(user: User): LoginContext {
        if (!walletService.hasLoginContext()) {
            walletService.login(user.toLoginParams())
        }
        return walletService.getLoginContext()
    }

    suspend fun authLoginWithWallet (user: User): LoginContext {
        val ctx = authLogin(user)
        if (ctx.maybeWalletInfo == null) {
            ctx.walletInfo = walletService.listWallets().first()
        }
        return ctx
    }

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}