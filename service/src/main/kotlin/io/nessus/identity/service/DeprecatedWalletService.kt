package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.W3CCredentialJwt

// WalletService =======================================================================================================

interface DeprecatedWalletService {

    fun addCredentialOffer(ctx: LoginContext, credOffer: CredentialOffer): String

    fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOffer>

    fun getCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer?

    fun deleteCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer?

    fun deleteCredentialOffers(ctx: LoginContext, predicate: (CredentialOffer) -> Boolean)

    suspend fun findCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): List<WalletCredential>

    suspend fun findCredential(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): WalletCredential?

    suspend fun getCredentialById(ctx: LoginContext, vcId: String): W3CCredentialJwt?

    suspend fun getCredentialByType(ctx: LoginContext, ctype: String): W3CCredentialJwt?

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): W3CCredentialJwt?

    suspend fun deleteCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean)
}
