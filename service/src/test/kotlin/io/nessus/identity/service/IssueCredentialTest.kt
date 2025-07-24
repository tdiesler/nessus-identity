package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssueCredentialTest : AbstractServiceTest() {

    /**
     * Issue Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     *
     * Wallet Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#in-time
     *
     * - The Holder has received a CredentialOffer and sends an AuthorizationRequest to the Issuer
     * - The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
     * - Holder issues an IDToken signed by the DID's authentication key
     * - Issuer validates IDToken and returns an Authorization Code
     * - Holder sends a TokenRequest to the Issuer's Token Endpoint
     * - Issuer validates the TokenRequest and responds with an Access Token
     * - Holder sends the CredentialRequest using the Access Token
     * - Issuer sends the requested Credential
     */
    @Test
    fun issueCredentialInTime() {
        runBlocking {

            // Create the Issuer's OIDC context
            //
            val ictx = OIDCContext(setupWalletWithDid(Max))
            val issuerMetadata = IssuerService.getIssuerMetadata(ictx)
            ictx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

            // Create the Holders's OIDC context
            //
            val hctx = OIDCContext(setupWalletWithDid(Alice))
            hctx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

            // Issuer creates the CredentialOffer
            //
            val sub= hctx.did
            val types = listOf("VerifiableCredential", "CTWalletSameAuthorisedInTime")
            val credOffer = IssuerService.createCredentialOffer(ictx, sub, types)

            // The Holder has received a CredentialOffer and sends an AuthorizationRequest to the Issuer
            //
            WalletService.addCredentialOffer(hctx, credOffer)
            val offeredCred = WalletService.resolveOfferedCredential(hctx, credOffer)
            val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, issuerMetadata.credentialIssuer)
            val authRequest = WalletService.buildAuthorizationRequest(hctx, authDetails)

            // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
            //
            AuthService.validateAuthorizationRequest(ictx, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequest(ictx, authRequest)
            val idTokenRequestUrl = AuthService.buildIDTokenRequestUrl(ictx, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = AuthService.createIDToken(hctx, urlQueryToMap(idTokenRequestUrl))

            // Issuer validates IDToken and returns an Authorization Code
            // [TODO] Validate the IDToken - AuthService.validateIDToken does actually not do that just yet
            val authCode = AuthService.validateIDToken(ictx, idTokenJwt)
            idTokenJwt.verifyJwt(hctx.didInfo) shouldBe true

            // Holder sends a TokenRequest to the Issuer's Token Endpoint
            //
            val tokenReq = AuthService.createTokenRequestAuthCode(hctx, authCode)

            // Issuer validates the TokenRequest and responds with an Access Token
            //
            val accessTokenRes = AuthService.handleTokenRequestAuthCode(ictx, tokenReq)

            // Holder sends the CredentialRequest using the Access Token
            //
            val credReq = WalletService.buildCredentialRequest(hctx, offeredCred, accessTokenRes)

            // Issuer sends the requested Credential
            //
            val accessJwt = SignedJWT.parse(accessTokenRes.accessToken)
            val credRes = IssuerService.credentialFromRequest(ictx, credReq, accessJwt)
            val credJwt = SignedJWT.parse("${credRes.credential}")

            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain "CTWalletSameAuthorisedInTime"
            vcSubject shouldBe hctx.did
            vcIssuer shouldBe ictx.did
        }
    }
}