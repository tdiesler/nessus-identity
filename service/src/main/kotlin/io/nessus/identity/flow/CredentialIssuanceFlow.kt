package io.nessus.identity.flow

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AuthService
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadataDraft11
import kotlinx.coroutines.runBlocking

class CredentialIssuanceFlow(val holderCtx: OIDContext, val issuerCtx: OIDContext) {

    val issuerSrv = IssuerService.create()
    val walletSrv = WalletService.create()

    init {
        val metadata = runBlocking { issuerSrv.getIssuerMetadata(issuerCtx) as IssuerMetadataDraft11 }
        issuerCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
        holderCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(credOffer: CredentialOffer): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        walletSrv.addCredentialOffer(holderCtx, credOffer)
        val offeredCred = walletSrv.resolveOfferedCredential(holderCtx, credOffer)
        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer)
        val authRequest = AuthorizationRequestBuilder(holderCtx)
            .withAuthorizationDetails(authDetails)
            .withCredentialOffer(credOffer)
            .build()

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        AuthService.validateAuthorizationRequest(issuerCtx, authRequest)
        val idTokenRequestJwt = AuthService.buildIDTokenRequest(issuerCtx, authRequest)
        val idTokenRequestUrl = AuthService.buildIDTokenRedirectUrl(issuerCtx, idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = walletSrv.createIDToken(holderCtx, urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = AuthService.validateIDToken(issuerCtx, idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holderCtx.didInfo)


        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = walletSrv.createTokenRequestAuthCode(holderCtx, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestAuthCode(issuerCtx, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = walletSrv.createCredentialRequest(holderCtx, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSrv.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt)

        return credRes
    }

    /**
     * Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferDeferred(credOffer: CredentialOffer): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        walletSrv.addCredentialOffer(holderCtx, credOffer)
        val offeredCred = walletSrv.resolveOfferedCredential(holderCtx, credOffer)
        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer)
        val authRequest = AuthorizationRequestBuilder(holderCtx)
            .withAuthorizationDetails(authDetails)
            .withCredentialOffer(credOffer)
            .build()

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        AuthService.validateAuthorizationRequest(issuerCtx, authRequest)
        val idTokenRequestJwt = AuthService.buildIDTokenRequest(issuerCtx, authRequest)
        val idTokenRequestUrl = AuthService.buildIDTokenRedirectUrl(issuerCtx, idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = walletSrv.createIDToken(holderCtx, urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = AuthService.validateIDToken(issuerCtx, idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holderCtx.didInfo)

        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = walletSrv.createTokenRequestAuthCode(holderCtx, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestAuthCode(issuerCtx, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = walletSrv.createCredentialRequest(holderCtx, offeredCred, accessTokenRes)

        // Issuer responds with a deferred CredentialResponse that contains an AcceptanceToken
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSrv.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt, true)

        return credRes
    }

    /**
     * Pre-Authorized Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     */
    suspend fun credentialFromOfferPreAuthorized(credOffer: CredentialOffer, userPin: String): CredentialResponse {

        // The Holder received a CredentialOffer
        //
        walletSrv.addCredentialOffer(holderCtx, credOffer)
        val offeredCred = walletSrv.resolveOfferedCredential(holderCtx, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSrv.createTokenRequestPreAuthorized(holderCtx, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestPreAuthorized(issuerCtx, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = walletSrv.createCredentialRequest(holderCtx, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSrv.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt)

        return credRes
    }


    /**
     * Pre-Authorized Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferPreAuthorizedDeferred(
        credOffer: CredentialOffer,
        userPin: String
    ): CredentialResponse {

        // The Holder received a CredentialOffer
        //
        walletSrv.addCredentialOffer(holderCtx, credOffer)
        val offeredCred = walletSrv.resolveOfferedCredential(holderCtx, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSrv.createTokenRequestPreAuthorized(holderCtx, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestPreAuthorized(issuerCtx, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = walletSrv.createCredentialRequest(holderCtx, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = issuerSrv.getCredentialFromRequest(issuerCtx, credReq, accessTokenJwt, true)

        return credRes
    }
}