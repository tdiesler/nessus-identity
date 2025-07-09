package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.FlowContext

// WalletApi ===========================================================================================================

interface WalletServiceApi {

    suspend fun getCredentialFromUri(ctx: FlowContext, offerUri: String): CredentialResponse

    suspend fun getCredentialFromOffer(ctx: FlowContext, credOffer: CredentialOffer): CredentialResponse

    suspend fun getDeferredCredential(cex: FlowContext, acceptanceToken: String): CredentialResponse
}