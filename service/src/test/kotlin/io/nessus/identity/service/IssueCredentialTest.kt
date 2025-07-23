package io.nessus.identity.service

import id.walt.oid4vc.data.GrantType
import io.kotest.matchers.shouldBe
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssueCredentialTest : AbstractServiceTest() {

    /**
     * Issue Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows
     *
     * - The Holder has received a CredentialOffer and sends an AuthorizationRequest to the Issuer
     * - The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
     * - Holder issues an ID Token signed by the DID's authentication key
     * - Holder calls the IAuth's Token Endpoint to obtain an Access Token
     * - IAuth validates the request and responds with an Access Token
     * - Holder sends the Credential Request
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
            val types = listOf("TestCredential")
            val credOffer = IssuerService.createCredentialOffer(ictx, sub, types)

            // The Holder has received a CredentialOffer and sends an AuthorizationRequest to the Issuer
            //
            val offeredCred = WalletService.resolveOfferedCredential(hctx, credOffer)
            val issuerState = credOffer.grants[GrantType.authorization_code.value]?.issuerState
            val authRequest = WalletService.buildAuthorizationRequestFromCredentialOffer(hctx, offeredCred, issuerState)

            // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
            //
            AuthService.validateAuthorizationRequest(ictx, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequestJwt(ictx, authRequest)
            val idTokenRequestUrl = AuthService.buildIDTokenRequestUrl(ictx, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            val idTokenJwt = AuthService.createIDTokenFromRequest(hctx, urlQueryToMap(idTokenRequestUrl))
            idTokenJwt.verifyJwt(hctx.didInfo) shouldBe true
        }
    }
}