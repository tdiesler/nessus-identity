package io.nessus.identity.service

import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AuthServiceEbsi32.Companion.authEndpointUri
import io.nessus.identity.types.AuthorizationRequestDraft11Builder
import io.nessus.identity.types.CredentialOfferDraft11
import kotlinx.coroutines.runBlocking
import kotlin.random.Random

class CredentialIssuanceFlowEbsi32(val holderCtx: OIDContext, val issuerCtx: OIDContext) {

    val authSvc = AuthServiceEbsi32.create(issuerCtx)
    val issuerSvc = IssuerService.createEbsi()
    val walletSvc = WalletService.createEbsi()

    init {
        val metadata = runBlocking { issuerSvc.getIssuerMetadata(issuerCtx) }
        issuerCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
        holderCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(
        credOffer: CredentialOfferDraft11
    ): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        walletSvc.addCredentialOffer(holderCtx, credOffer)
        val issuerMetadata = issuerCtx.issuerMetadata

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()

        val redirectUri = "$authEndpointUri/${holderCtx.targetId}"
        val authRequest = AuthorizationRequestDraft11Builder()
            .withClientId(holderCtx.did)
            .withClientState(holderCtx.walletId)
            .withCodeChallengeMethod("S256")
            .withCodeVerifier(codeVerifier)
            .withIssuerMetadata(issuerMetadata)
            .withRedirectUri(redirectUri)
            .buildFrom(credOffer)

        holderCtx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        holderCtx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        authSvc.validateAuthorizationRequest(authRequest)
        val idTokenRequestJwt = authSvc.buildIDTokenRequest(authRequest)
        val idTokenRequestUrl = authSvc.buildIDTokenRedirectUrl(idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = walletSvc.createIDToken(holderCtx,urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = authSvc.validateIDToken(idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holderCtx.didInfo)

        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = walletSvc.createTokenRequestAuthCode(holderCtx, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = authSvc.handleTokenRequestAuthCode(tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.credentialConfigurationIds
        val credReq = walletSvc.createCredentialRequest(holderCtx, types, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSvc.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt)

        return credRes
    }

    /**
     * Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferDeferred(
        credOffer: CredentialOfferDraft11
    ): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        walletSvc.addCredentialOffer(holderCtx, credOffer)

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()

        val redirectUri = "$authEndpointUri/${holderCtx.targetId}"
        val authRequest = AuthorizationRequestDraft11Builder()
            .withClientId(holderCtx.did)
            .withClientState(holderCtx.walletId)
            .withCodeChallengeMethod("S256")
            .withCodeVerifier(codeVerifier)
            .withIssuerMetadata(issuerCtx.issuerMetadata)
            .withRedirectUri(redirectUri)
            .buildFrom(credOffer)

        holderCtx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        holderCtx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        authSvc.validateAuthorizationRequest(authRequest)
        val idTokenRequestJwt = authSvc.buildIDTokenRequest(authRequest)
        val idTokenRequestUrl = authSvc.buildIDTokenRedirectUrl(idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = walletSvc.createIDToken(holderCtx,urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = authSvc.validateIDToken(idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holderCtx.didInfo)

        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = walletSvc.createTokenRequestAuthCode(holderCtx, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = authSvc.handleTokenRequestAuthCode(tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.credentialConfigurationIds
        val credReq = walletSvc.createCredentialRequest(holderCtx, types, accessTokenRes)

        // Issuer responds with a deferred CredentialResponse that contains an AcceptanceToken
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSvc.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt, true)

        return credRes
    }

    /**
     * Pre-Authorized Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     */
    suspend fun credentialFromOfferPreAuthorized(
        credOffer: CredentialOfferDraft11,
        userPin: String
    ): CredentialResponse {

        // The Holder received a CredentialOffer
        //
        walletSvc.addCredentialOffer(holderCtx, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSvc.createTokenRequestPreAuthorized(holderCtx, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = authSvc.handleTokenRequestPreAuthorized(tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.credentialConfigurationIds
        val credReq = walletSvc.createCredentialRequest(holderCtx, types, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSvc.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt)

        return credRes
    }


    /**
     * Pre-Authorized Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferPreAuthorizedDeferred(
        credOffer: CredentialOfferDraft11,
        userPin: String
    ): CredentialResponse {

        // The Holder received a CredentialOffer
        //
        walletSvc.addCredentialOffer(holderCtx, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSvc.createTokenRequestPreAuthorized(holderCtx, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = authSvc.handleTokenRequestPreAuthorized(tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.credentialConfigurationIds
        val credReq = walletSvc.createCredentialRequest(holderCtx, types, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSvc.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt, true)

        return credRes
    }
}