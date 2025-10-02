package io.nessus.identity.service

import io.nessus.identity.types.CredentialOffer
import kotlin.uuid.ExperimentalUuidApi

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(credOffer: COType): String

    fun getCredentialOffers(): Map<String, COType>

    fun getCredentialOffer(offerId: String): COType?

    fun deleteCredentialOffer(offerId: String): COType?

    companion object {
        fun createEbsi(): WalletServiceEbsi32 {
            return WalletServiceEbsi32()
        }
        fun createKeycloak(): WalletServiceKeycloak {
            return WalletServiceKeycloak()
        }
    }
}
