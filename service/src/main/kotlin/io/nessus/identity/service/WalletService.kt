package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

// WalletService =======================================================================================================

interface WalletService<COType: CredentialOffer> {

    fun addCredentialOffer(ctx: OIDContext, credOffer: COType)

    fun addCredential(ctx: OIDContext, credRes: CredentialResponse)

    suspend fun createIDToken(ctx: OIDContext, reqParams: Map<String, String>): SignedJWT

    suspend fun createVPToken(ctx: OIDContext, authReq: AuthorizationRequest): SignedJWT

    fun createTokenRequestAuthCode(ctx: OIDContext, authCode: String): TokenRequest

    fun createTokenRequestPreAuthorized(ctx: OIDContext, credOffer: COType, userPin: String): TokenRequest

    suspend fun getCredentialOfferFromUri(ctx: OIDContext, offerUri: String): COType

    suspend fun getCredentialFromOffer(ctx: OIDContext, credOffer: COType): CredentialResponse

    suspend fun getDeferredCredential(ctx: OIDContext, acceptanceToken: String): CredentialResponse

    suspend fun createCredentialRequest(ctx: OIDContext, offeredCred: OfferedCredential, accessToken: TokenResponse): CredentialRequest

    suspend fun resolveIssuerMetadata(issuerUrl: String): IssuerMetadata

    suspend fun resolveOfferedCredential(ctx: OIDContext, credOffer: COType): OfferedCredential

    suspend fun sendIDToken(ctx: OIDContext, redirectUri: String, idTokenJwt: SignedJWT): String

    suspend fun sendVPToken(ctx: OIDContext, vpTokenJwt: SignedJWT): String

    companion object {
        fun create(): DefaultWalletService {
            return DefaultWalletService()
        }
    }
}
