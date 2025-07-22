package io.nessus.identity.service

import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlin.collections.set

object ContextRegistry {

    private val registry = ConcurrentHashMap<String, OIDCContext>()

    fun <T : OIDCContext> putContext(ctxId: String, ctx: T) {
        registry[ctxId] = ctx
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : OIDCContext> getContext(ctxId: String): T? {
        return registry[ctxId] as? T
    }

    /**
     * Short hash from the combination of walletId + did
     * [TODO] do we really need the walletId
     * [TODO] complain about not being able to use base64
     * [TODO] use a more explicit hex encoder
     */
    fun getTargetId(wid: String, did: String): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val subHash = sha256.digest("$wid|$did".toByteArray(Charsets.US_ASCII))
        return subHash.joinToString("") { "%02x".format(it) }.substring(0, 12)
    }
}