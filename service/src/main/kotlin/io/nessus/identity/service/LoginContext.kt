package io.nessus.identity.service

import java.security.MessageDigest

open class LoginContext() {

    constructor(authToken: String, walletInfo: WalletInfo, didInfo: DidInfo) : this() {
        _authToken = authToken
        _walletInfo = walletInfo
        _didInfo = didInfo
    }

    private var _authToken: String? = null // The wallet-api auth token
    private var _walletInfo: WalletInfo? = null
    private var _didInfo: DidInfo? = null

    val maybeAuthToken get() = _authToken
    val maybeWalletInfo get() = _walletInfo
    val maybeDidInfo get() = _didInfo

    val hasWalletInfo get() = _walletInfo != null
    val hasDidInfo get() = _didInfo != null

    var authToken: String
        get() = _authToken ?: throw IllegalStateException("No authToken")
        set(token) {
            _authToken = token
        }

    var walletInfo: WalletInfo
        get() = _walletInfo ?: throw IllegalStateException("No walletInfo")
        set(wi) {
            _walletInfo = wi
            registry[subjectId] = this
        }

    var didInfo: DidInfo
        get() = _didInfo ?: throw IllegalStateException("No didInfo")
        set(di) {
            _didInfo = di
            registry[subjectId] = this
        }

    val did get() = didInfo.did
    val walletId get() = walletInfo.id
    val subjectId get() = getSubjectId(walletId, maybeDidInfo?.did ?: "")

    companion object {

        // A global registry that allows us to restore a LoginContext from subjectId
        private val registry = mutableMapOf<String, LoginContext>()

        /**
         * Short hash from the combination of walletId + did
         * [TODO] do we really need the walletId
         * [TODO] complain about not being able to use base64
         * [TODO] use a more explicit hex encoder
         */
        fun getSubjectId(wid: String, did: String): String {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val subHash = sha256.digest("$wid|$did".toByteArray(Charsets.US_ASCII))
            return subHash.joinToString("") { "%02x".format(it) }.substring(0, 12)
        }

        fun findLoginContext(subjectId: String): LoginContext? {
            return registry[subjectId]
        }

        fun findLoginContext(walletId: String, did: String): LoginContext? {
            val subjectId = getSubjectId(walletId, did)
            return findLoginContext(subjectId)
        }
    }

    open fun close() {
        _didInfo?.also {
            registry.remove(subjectId)
        }
        _authToken = null
        _didInfo = null
    }
}