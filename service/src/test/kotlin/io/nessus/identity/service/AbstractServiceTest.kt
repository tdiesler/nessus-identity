package io.nessus.identity.service


import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.KeyType
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import java.nio.file.Files
import java.nio.file.Paths

abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    suspend fun login(user: User): LoginContext {
        var ctx = getLoginContext(user)
        if (ctx == null) {
            ctx = widWalletSvc.login(user.toLoginParams())
            sessions[user.email] = ctx
        }
        return ctx
    }

    suspend fun loginWithWallet (user: User): LoginContext {
        val ctx = login(user).also {
            it.walletInfo = widWalletSvc.listWallets(it).first()
        }
        if (ctx.maybeDidInfo == null) {
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
                ctx.didInfo = it
            }
        }
        return ctx
    }

    fun clearLoginContexts() {
        return sessions.clear()
    }

    fun getLoginContext(user: User): LoginContext? {
        return sessions[user.email]
    }

    fun hasLoginContext(user: User): Boolean {
        return sessions.contains(user.email)
    }

    suspend fun setupWalletWithDid (user: User): LoginContext {
        val ctx = runCatching { loginWithWallet(user) }.getOrElse { ex ->
            val apiEx = ex as? APIException ?: throw ex
            val msg = apiEx.message as String
            if (apiEx.code == 401 && msg.contains("Unknown user")) {
                widWalletSvc.registerUser(user.toRegisterUserParams())
                loginWithWallet(user)
            } else {
                throw ex
            }
        }
        if (ctx.maybeDidInfo == null) {
            val didInfo = widWalletSvc.findDidByPrefix(ctx, "did:key")
            if (didInfo == null) {
                val key = widWalletSvc.findKeyByType(ctx, KeyType.SECP256R1)
                    ?: widWalletSvc.createKey(ctx, KeyType.SECP256R1)
                ctx.didInfo = widWalletSvc.createDidKey(ctx, "", key.id)
            } else {
                ctx.didInfo = didInfo
            }
        }
        return ctx
    }

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}