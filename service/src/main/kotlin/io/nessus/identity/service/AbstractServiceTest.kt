package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.KeyType
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Paths

abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    fun login(user: User): LoginContext {
        val ctx = sessions[user.email] ?: runBlocking {
            widWalletSvc.login(user.toLoginParams()).also {
                sessions[user.email] = it
            }
        }
        return ctx
    }

    suspend fun loginWithWallet(user: User): LoginContext {
        val ctx = login(user).also {
            val wi = widWalletSvc.listWallets(it).first()
            it.putAttachment(AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        if (ctx.maybeDidInfo == null) {
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
                ctx.putAttachment(AttachmentKeys.DID_INFO_ATTACHMENT_KEY, it)
            }
        }
        return ctx
    }

    suspend fun loginWithDid(user: User): LoginContext {
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
            ctx.putAttachment(AttachmentKeys.DID_INFO_ATTACHMENT_KEY, didInfo)
        }
        return ctx
    }

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}