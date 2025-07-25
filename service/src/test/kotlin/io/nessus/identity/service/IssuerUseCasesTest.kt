package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssuerUseCasesTest : AbstractServiceTest() {

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
     * - Holder validates the received Credential
     * - Holder adds the Credential to permanent storage
     */
    @Test
    fun issueCredentialInTime() {
        runBlocking {

            // Create the Issuer's OIDC context
            //
            val max = OIDCContext(setupWalletWithDid(Max))
            val issuerMetadata = IssuerService.getIssuerMetadata(max)
            max.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

            // Create the Holders's OIDC context
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))
            alice.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

            // Issuer creates the CredentialOffer
            //
            val sub= alice.did
            val types = listOf("VerifiableCredential", "CTWalletSameAuthorisedInTime")
            val credOffer = IssuerService.createCredentialOffer(max, sub, types)

            // The Holder has received a CredentialOffer and sends an AuthorizationRequest to the Issuer
            //
            WalletService.addCredentialOffer(alice, credOffer)
            val offeredCred = WalletService.resolveOfferedCredential(alice, credOffer)
            val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer)
            val authRequest = AuthorizationRequestBuilder(alice)
                .withAuthorizationDetails(authDetails)
                .withCredentialOffer(credOffer)
                .build()

            // The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
            //
            AuthService.validateAuthorizationRequest(max, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequest(max, authRequest)
            val idTokenRequestUrl = AuthService.buildIDTokenRedirectUrl(max, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = WalletService.createIDToken(alice, urlQueryToMap(idTokenRequestUrl))

            // Issuer validates IDToken and returns an Authorization Code
            val authCode = AuthService.validateIDToken(max, idTokenJwt)
            idTokenJwt.verifyJwt(alice.didInfo) shouldBe true

            // Holder sends a TokenRequest to the Issuer's Token Endpoint
            //
            val tokenReq = WalletService.createTokenRequestAuthCode(alice, authCode)

            // Issuer validates the TokenRequest and responds with an Access Token
            //
            val accessTokenRes = AuthService.handleTokenRequestAuthCode(max, tokenReq)

            // Holder sends the CredentialRequest using the Access Token
            //
            val credReq = WalletService.buildCredentialRequest(alice, offeredCred, accessTokenRes)

            // Issuer sends the requested Credential
            //
            val accessJwt = SignedJWT.parse(accessTokenRes.accessToken)
            val credRes = IssuerService.credentialFromRequest(max, credReq, accessJwt)
            val credJwt = SignedJWT.parse("${credRes.credential}")

            // Holder validates the received Credential
            //
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain "CTWalletSameAuthorisedInTime"
            vcSubject shouldBe alice.did
            vcIssuer shouldBe max.did

            // Holder adds the Credential to permanent storage
            //
            WalletService.addCredential(alice, credRes)
        }
    }
}