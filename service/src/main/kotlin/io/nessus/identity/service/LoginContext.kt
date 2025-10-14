package io.nessus.identity.service

import io.nessus.identity.service.AttachmentKeys.AUTH_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.KeyType
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import java.security.MessageDigest

open class LoginContext(attachments: Map<AttachmentKey<*>, Any> = mapOf()) : AttachmentContext(attachments) {

    val maybeWalletInfo get() = getAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val maybeDidInfo get() = getAttachment(DID_INFO_ATTACHMENT_KEY)

    val hasWalletInfo get() = hasAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val hasDidInfo get() = hasAttachment(DID_INFO_ATTACHMENT_KEY)

    val authToken get() = assertAttachment(AUTH_TOKEN_ATTACHMENT_KEY)
    val walletInfo get() = assertAttachment(WALLET_INFO_ATTACHMENT_KEY)
    val didInfo get() = assertAttachment(DID_INFO_ATTACHMENT_KEY)

    val did get() = didInfo.did
    val walletId get() = walletInfo.id
    val targetId get() = getTargetId(walletId, maybeDidInfo?.did ?: "")

    companion object {

        suspend fun login(user: User): LoginContext {
            val ctx = widWalletService.login(user.toLoginParams())
            return ctx
        }

        suspend fun loginOrRegister(user: User): LoginContext {
            val ctx = runCatching { widWalletService.login(user.toLoginParams()) }.getOrElse { ex ->
                val apiEx = ex as? APIException ?: throw ex
                val msg = apiEx.message as String
                if (apiEx.code == 401 && msg.contains("Unknown user")) {
                    widWalletService.registerUser(user.toRegisterUserParams())
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

    open fun close() {
        removeAttachment(AUTH_TOKEN_ATTACHMENT_KEY)
        removeAttachment(DID_INFO_ATTACHMENT_KEY)
    }
}