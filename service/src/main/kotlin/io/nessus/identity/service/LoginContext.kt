package io.nessus.identity.service

import io.nessus.identity.service.AttachmentKeys.AUTH_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
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
        /**
         * Short hash from the combination of walletId + did
         */
        fun getTargetId(wid: String, did: String): String {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val subHash = sha256.digest("$wid|$did".toByteArray(Charsets.US_ASCII))
            return subHash.joinToString("") { "%02x".format(it) }.substring(0, 12)
        }
    }

    open fun close() {
        removeAttachment(AUTH_TOKEN_ATTACHMENT_KEY)
        removeAttachment(DID_INFO_ATTACHMENT_KEY)
    }
}