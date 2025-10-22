package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(ctx: LoginContext, credOffer: COType): String

    fun getCredentialOffers(ctx: LoginContext): Map<String, COType>

    fun getCredentialOffer(ctx: LoginContext, offerId: String): COType?

    fun deleteCredentialOffer(ctx: LoginContext, offerId: String): COType?

    suspend fun findCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): List<WalletCredential>

    suspend fun findCredential(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): WalletCredential?

    suspend fun getCredentialById(ctx: LoginContext, vcId: String): VCDataJwt?

    suspend fun getCredentialByType(ctx: LoginContext, ctype: String): VCDataJwt?

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): VCDataJwt?

    suspend fun deleteCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean)

    companion object {
        fun createEbsi(): WalletServiceEbsi32 {
            return WalletServiceEbsi32()
        }
        fun createKeycloak(): WalletServiceKeycloak {
            return WalletServiceKeycloak()
        }
    }
}
