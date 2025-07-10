package io.nessus.identity.service

import io.nessus.identity.waltid.DidInfo
import io.nessus.identity.waltid.WalletInfo
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
        }

    var didInfo: DidInfo
        get() = _didInfo ?: throw IllegalStateException("No didInfo")
        set(di) {
            _didInfo = di
        }

    val did get() = didInfo.did
    val walletId get() = walletInfo.id
    val subjectId get() = getSubjectId(walletId, maybeDidInfo?.did ?: "")

    companion object {
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
    }

    open fun close() {
        _authToken = null
        _didInfo = null
    }
}