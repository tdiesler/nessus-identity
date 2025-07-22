package io.nessus.identity.service


import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
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
            val wi = widWalletSvc.listWallets(it).first()
            it.putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        if (ctx.maybeDidInfo == null) {
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
                ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, it)
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
            var didInfo = widWalletSvc.findDidByPrefix(ctx, "did:key")
            if (didInfo == null) {
                val key = widWalletSvc.findKeyByType(ctx, KeyType.SECP256R1)
                    ?: widWalletSvc.createKey(ctx, KeyType.SECP256R1)
                didInfo = widWalletSvc.createDidKey(ctx, "", key.id)
            }
            ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, didInfo)
        }
        return ctx
    }

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}