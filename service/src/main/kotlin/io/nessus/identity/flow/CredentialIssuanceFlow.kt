package io.nessus.identity.flow

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AuthService
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestBuilder

class CredentialIssuanceFlow(val holder: OIDCContext, val issuer: OIDCContext) {

    init {
        val issuerMetadata = IssuerService.getIssuerMetadata(issuer)
        issuer.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
        holder.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(credOffer: CredentialOffer): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        WalletService.addCredentialOffer(holder, credOffer)
        val offeredCred = WalletService.resolveOfferedCredential(holder, credOffer)
        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer)
        val authRequest = AuthorizationRequestBuilder(holder)
            .withAuthorizationDetails(authDetails)
            .withCredentialOffer(credOffer)
            .build()

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        AuthService.validateAuthorizationRequest(issuer, authRequest)
        val idTokenRequestJwt = AuthService.buildIDTokenRequest(issuer, authRequest)
        val idTokenRequestUrl = AuthService.buildIDTokenRedirectUrl(issuer, idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = WalletService.createIDToken(holder, urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = AuthService.validateIDToken(issuer, idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holder.didInfo)


        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = WalletService.createTokenRequestAuthCode(holder, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestAuthCode(issuer, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = WalletService.createCredentialRequest(holder, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = IssuerService.credentialFromRequest(issuer, credReq, accessTokenJwt)

        return credRes
    }

    /**
     * Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferDeferred(credOffer: CredentialOffer): CredentialResponse {

        // The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
        //
        WalletService.addCredentialOffer(holder, credOffer)
        val offeredCred = WalletService.resolveOfferedCredential(holder, credOffer)
        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer)
        val authRequest = AuthorizationRequestBuilder(holder)
            .withAuthorizationDetails(authDetails)
            .withCredentialOffer(credOffer)
            .build()

        // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
        //
        AuthService.validateAuthorizationRequest(issuer, authRequest)
        val idTokenRequestJwt = AuthService.buildIDTokenRequest(issuer, authRequest)
        val idTokenRequestUrl = AuthService.buildIDTokenRedirectUrl(issuer, idTokenRequestJwt)

        // Holder issues an ID Token signed by the DID's authentication key
        //
        val idTokenJwt = WalletService.createIDToken(holder, urlQueryToMap(idTokenRequestUrl))

        // Issuer validates IDToken and returns an Authorization Code
        val authCode = AuthService.validateIDToken(issuer, idTokenJwt)
        idTokenJwt.verifyJwtSignature("IDToken", holder.didInfo)

        // Holder sends a TokenRequest to the Issuer's Token Endpoint
        //
        val tokenReq = WalletService.createTokenRequestAuthCode(holder, authCode)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestAuthCode(issuer, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = WalletService.createCredentialRequest(holder, offeredCred, accessTokenRes)

        // Issuer responds with a deferred CredentialResponse that contains an AcceptanceToken
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = IssuerService.credentialFromRequest(issuer, credReq, accessTokenJwt, true)

        return credRes
    }

    /**
     * Pre-Authorized Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     */
    suspend fun credentialFromOfferPreAuthorized(credOffer: CredentialOffer, userPin: String): CredentialResponse {
        
        // The Holder received a CredentialOffer
        //
        WalletService.addCredentialOffer(holder, credOffer)
        val offeredCred = WalletService.resolveOfferedCredential(holder, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = WalletService.createTokenRequestPreAuthorized(holder, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestPreAuthorized(issuer, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = WalletService.createCredentialRequest(holder, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = IssuerService.credentialFromRequest(issuer, credReq, accessTokenJwt)

        return credRes
    }


    /**
     * Pre-Authorized Holder gets a deferred Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     */
    suspend fun credentialFromOfferPreAuthorizedDeferred(credOffer: CredentialOffer, userPin: String): CredentialResponse {

        // The Holder received a CredentialOffer
        //
        WalletService.addCredentialOffer(holder, credOffer)
        val offeredCred = WalletService.resolveOfferedCredential(holder, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = WalletService.createTokenRequestPreAuthorized(holder, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestPreAuthorized(issuer, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val credReq = WalletService.createCredentialRequest(holder, offeredCred, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val accessTokenJwt = SignedJWT.parse(accessTokenRes.accessToken)
        val credRes = IssuerService.credentialFromRequest(issuer, credReq, accessTokenJwt, true)

        return credRes
    }
}