package io.nessus.identity.service

import io.nessus.identity.types.CredentialOffer

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(credOffer: COType): String

    companion object {
        fun createEbsi(ctx: OIDContext): WalletServiceEbsi32 {
            return WalletServiceEbsi32(ctx)
        }
        fun createKeycloak(ctx: OIDContext): WalletServiceKeycloak {
            return WalletServiceKeycloak(ctx)
        }
    }
}
