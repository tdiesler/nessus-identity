package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.AuthContext

// WalletApi ===========================================================================================================

interface WalletServiceApi {

    suspend fun getCredentialFromUri(ctx: AuthContext, offerUri: String): CredentialResponse

    suspend fun getCredentialFromOffer(ctx: AuthContext, credOffer: CredentialOffer): CredentialResponse

    suspend fun getDeferredCredential(ctx: AuthContext, acceptanceToken: String): CredentialResponse
}