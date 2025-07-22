package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.OIDCContext

// WalletApi ===========================================================================================================

interface WalletServiceApi {

    suspend fun getCredentialFromUri(ctx: OIDCContext, offerUri: String): CredentialResponse

    suspend fun getCredentialFromOffer(ctx: OIDCContext, credOffer: CredentialOffer): CredentialResponse

    suspend fun getDeferredCredential(ctx: OIDCContext, acceptanceToken: String): CredentialResponse
}