package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(credOffer: COType): String

    fun getCredentialOffers(): Map<String, COType>

    fun getCredentialOffer(offerId: String): COType?

    fun deleteCredentialOffer(offerId: String): COType?

    suspend fun findCredentials(ctx: LoginContext, predicate: (VCDataJwt) -> Boolean): List<VCDataJwt>

    suspend fun findCredential(ctx: LoginContext, predicate: (VCDataJwt) -> Boolean): VCDataJwt?

    suspend fun getCredentialById(ctx: LoginContext, vcId: String): VCDataJwt?

    suspend fun getCredentialByType(ctx: LoginContext, ctype: String): VCDataJwt?

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): VCDataJwt?

    suspend fun deleteCredentials(ctx: LoginContext, predicate: (VCDataJwt) -> Boolean)

    companion object {
        fun createEbsi(): WalletServiceEbsi32 {
            return WalletServiceEbsi32()
        }
        fun createKeycloak(): WalletServiceKeycloak {
            return WalletServiceKeycloak()
        }
    }
}
