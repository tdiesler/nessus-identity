package io.nessus.identity

import io.nessus.identity.config.User
import io.nessus.identity.types.AttachmentKey
import io.nessus.identity.types.AttachmentSupport
import io.nessus.identity.types.DidInfo
import io.nessus.identity.types.KeyType
import io.nessus.identity.types.LoginParams
import io.nessus.identity.types.LoginType
import io.nessus.identity.types.RegisterUserParams
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.WalletInfo
import io.nessus.identity.types.attachmentKey
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import java.security.MessageDigest

open class LoginContext(attachments: Map<AttachmentKey<*>, Any> = mapOf()) : AttachmentSupport(attachments) {

    val maybeWalletInfo get() = getAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val maybeDidInfo get() = getAttachment(DID_INFO_ATTACHMENT_KEY)

    val hasAuthToken get() = hasAttachment(AUTH_TOKEN_ATTACHMENT_KEY)
    val hasWalletInfo get() = hasAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val hasDidInfo get() = hasAttachment(DID_INFO_ATTACHMENT_KEY)

    val authToken get() = assertAttachment(AUTH_TOKEN_ATTACHMENT_KEY)
    val walletInfo get() = assertAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val didInfo get() = assertAttachment(DID_INFO_ATTACHMENT_KEY)
    val userRole get() = assertAttachment(USER_ROLE_ATTACHMENT_KEY)

    val did get() = didInfo.did
    val walletId get() = walletInfo.id
    val targetId get() = getTargetId(walletId, maybeDidInfo?.did ?: "")

    companion object {

        val AUTH_CONTEXT_ATTACHMENT_KEY = attachmentKey<AuthorizationContext>()
        val AUTH_TOKEN_ATTACHMENT_KEY = attachmentKey<String>("AUTH_TOKEN")
        val WALLET_INFO_ATTACHMENT_KEY = attachmentKey<WalletInfo>()
        val DID_INFO_ATTACHMENT_KEY = attachmentKey<DidInfo>()
        val TX_CODE_ATTACHMENT_KEY = attachmentKey<String>("TX_CODE")
        val USER_ROLE_ATTACHMENT_KEY = attachmentKey<UserRole>()
        val USER_ATTACHMENT_KEY = attachmentKey<User>()

        // [TODO] Move these to the AuthorizationContext
        val AUTH_RESPONSE_ATTACHMENT_KEY = attachmentKey<TokenResponse>()

        suspend fun login(user: User): LoginContext {
            return login(user.toLoginParams()).also {
                it.putAttachment(USER_ATTACHMENT_KEY, user)
            }
        }

        suspend fun login(params: LoginParams): LoginContext {
            val ctx = widWalletService.authLogin(params)
            return ctx
        }

        suspend fun loginOrRegister(user: User): LoginContext {
            val ctx = runCatching { widWalletService.authLogin(user.toLoginParams()) }.getOrElse { ex ->
                val apiEx = ex as? APIException ?: throw ex
                val msg = apiEx.message as String
                if (apiEx.code == 401 && msg.contains("Unknown user")) {
                    widWalletService.authRegister(user.toRegisterUserParams())
                    login(user)
                } else {
                    throw ex
                }
            }
            return ctx
        }

        /**
         * Short hash from the combination of walletId + did
         */
        fun getTargetId(wid: String, did: String): String {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val subHash = sha256.digest("$wid|$did".toByteArray(Charsets.US_ASCII))
            return subHash.joinToString("") { "%02x".format(it) }.substring(0, 12)
        }
    }

    suspend fun withWalletInfo(): LoginContext {
        getAttachment(WALLET_INFO_ATTACHMENT_KEY) ?: run {
            val wi = widWalletService.listWallets(this).first()
            putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        getAttachment(DID_INFO_ATTACHMENT_KEY) ?: run {
            widWalletService.findDidByPrefix(this, "did:key")?.also {
                putAttachment(DID_INFO_ATTACHMENT_KEY, it)
            }
        }
        return this
    }

    suspend fun withDidInfo(): LoginContext {
        withWalletInfo().also {
            getAttachment(DID_INFO_ATTACHMENT_KEY) ?: run {
                val key = widWalletService.findKeyByType(this, KeyType.SECP256R1)
                    ?: widWalletService.createKey(this, KeyType.SECP256R1)
                widWalletService.createDidKey(this, "", key.id).also {
                    putAttachment(DID_INFO_ATTACHMENT_KEY, it)
                }
            }
        }
        return this
    }

    fun withUserRole(role: UserRole): LoginContext {
        putAttachment(USER_ROLE_ATTACHMENT_KEY, role)
        return this
    }

    fun createAuthContext(): AuthorizationContext {
        val authContext = AuthorizationContext(this)
        putAttachment(AUTH_CONTEXT_ATTACHMENT_KEY, authContext)
        return authContext
    }

    fun getAuthContext(): AuthorizationContext {
        return getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) ?: createAuthContext()
    }
}

fun User.toLoginParams(): LoginParams {
    return LoginParams(LoginType.EMAIL, email, password)
}

fun User.toRegisterUserParams(): RegisterUserParams {
    return RegisterUserParams(LoginType.EMAIL, name, email, password)
}
