package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer

// ExperimentalWalletService ===========================================================================================

interface ExperimentalWalletService {

    suspend fun buildAuthorizationRequestFromOffer(ctx: LoginContext, credOffer: CredentialOffer): AuthorizationRequest
}