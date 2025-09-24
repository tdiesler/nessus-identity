package io.nessus.identity.service

import io.nessus.identity.types.CredentialOffer

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(credOffer: COType): String

    companion object {
        fun createEbsi(ctx: OIDContext): WalletServiceEbsi32 {
            return WalletServiceEbsi32(ctx)
        }
        fun create(ctx: OIDContext): WalletServiceDraft17 {
            return WalletServiceDraft17(ctx)
        }
    }
}
