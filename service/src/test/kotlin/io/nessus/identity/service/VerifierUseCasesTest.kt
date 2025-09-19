package io.nessus.identity.service

import id.walt.oid4vc.responses.CredentialResponse
import io.kotest.matchers.string.shouldContain
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.flow.CredentialIssuanceFlow
import io.nessus.identity.flow.CredentialVerificationFlow
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialStatus
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.time.Instant

class VerifierUseCasesTest : AbstractServiceTest() {

    val issuerSrv = IssuerService.create()
    val walletSrv = WalletService.create()

    /**
     * IDToken Exchange
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#generic-flow
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
     * - Holder issues an ID Token signed by the DID's authentication key
     * - Verifier validates the IDToken
     */
    @Test
    fun idTokenExchange() {
        runBlocking {

            // Create the Verifier's OIDC context
            //
            val bob = OIDContext(loginWithDid(Bob))

            // Create the Holders's OIDC context
            //
            val alice = OIDContext(loginWithDid(Alice))

            // The Holder sends an AuthorizationRequest to the Verifier
            //
            val redirectUri = "$authEndpointUri/${alice.targetId}"
            val authRequest = AuthorizationRequestBuilder()
                .withClientId(alice.did)
                .withRedirectUri(redirectUri)
                .build()

            // The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
            //
            AuthService.validateAuthorizationRequest(bob, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequest(bob, authRequest)
            val idTokenRedirectUrl = AuthService.buildIDTokenRedirectUrl(bob, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = walletSrv.createIDToken(alice, urlQueryToMap(idTokenRedirectUrl))

            // Verifier validates the IDToken
            //
            AuthService.validateIDToken(bob, idTokenJwt)
            idTokenJwt.verifyJwtSignature("IDToken", alice.didInfo)
        }
    }

    /**
     * Verify valid Credential in a Presentation
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#verifiable-presentations
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
     * - Holder responds with a signed VPToken that contains the VerifiablePresentation
     * - Verifier validates the VPToken
     */
    @Test
    fun validCredentialInPresentation() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDContext(loginWithDid(Max))

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDContext(loginWithDid(Alice))

            // Create the Verifier's OIDC context (Bob is the Verifier)
            //
            val bob = OIDContext(loginWithDid(Bob))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, types)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val issuanceFlow = CredentialIssuanceFlow(alice, max)
            val credRes = issuanceFlow.credentialFromOfferInTime(credOffer)
            walletSrv.addCredential(alice, credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationFlow(alice, bob)
            verificationFlow.verifyPresentationByType(ctype)
        }
    }

    /**
     * Verify expired Credential in a Presentation
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#verifiable-presentations
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
     * - Holder responds with a signed VPToken that contains the VerifiablePresentation
     * - Verifier validates the VPToken
     */
    @Test
    fun expiredCredentialInPresentation() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDContext(loginWithDid(Max))
            val userPin = "1234"

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDContext(loginWithDid(Alice))

            // Create the Verifier's OIDC context (Bob is the Verifier)
            //
            val bob = OIDContext(loginWithDid(Bob))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, types, userPin)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val now = Instant.now()
            val iat = now.plusSeconds(-10)
            val exp = now.plusSeconds(-5)
            val credRes = issueCredentialFromParameters(
                max, alice, credOffer, userPin, CredentialParameters()
                    .withIssuer(max.did)
                    .withSubject(alice.did)
                    .withTypes(types)
                    .withIssuedAt(iat)
                    .withValidUntil(exp)
            )
            walletSrv.addCredential(alice, credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationFlow(alice, bob)
            runCatching {
                verificationFlow.verifyPresentationByType(ctype)
            }.onFailure {
                log.error { it }
                it.message shouldContain "is expired"
            }.onSuccess {
                fail { "Expected expired credential" }
            }
        }
    }

    /**
     * Verify not-yet-valid Credential in a Presentation
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#verifiable-presentations
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
     * - Holder responds with a signed VPToken that contains the VerifiablePresentation
     * - Verifier validates the VPToken
     */
    @Test
    fun notYetValidCredentialInPresentation() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDContext(loginWithDid(Max))
            val userPin = "1234"

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDContext(loginWithDid(Alice))

            // Create the Verifier's OIDC context (Bob is the Verifier)
            //
            val bob = OIDContext(loginWithDid(Bob))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, types, userPin)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val iat = Instant.now()
            val nbf = iat.plusSeconds(10)
            val credRes = issueCredentialFromParameters(
                max, alice, credOffer, userPin, CredentialParameters()
                    .withIssuer(max.did)
                    .withSubject(alice.did)
                    .withTypes(types)
                    .withIssuedAt(iat)
                    .withValidFrom(nbf)
            )
            walletSrv.addCredential(alice, credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationFlow(alice, bob)
            runCatching {
                verificationFlow.verifyPresentationByType(ctype)
            }.onFailure {
                log.error { it }
                it.message shouldContain "not yet valid"
            }.onSuccess {
                fail { "Expected not yet valid credential" }
            }
        }
    }

    /**
     * Verify revoked Credential in a Presentation
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#verifiable-presentations
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
     * - Holder responds with a signed VPToken that contains the VerifiablePresentation
     * - Verifier validates the VPToken
     */
    @Test
    fun revokedCredentialInPresentation() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDContext(loginWithDid(Max))
            val userPin = "1234"

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDContext(loginWithDid(Alice))

            // Create the Verifier's OIDC context (Bob is the Verifier)
            //
            val bob = OIDContext(loginWithDid(Bob))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, types, userPin)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val credRes = issueCredentialFromParameters(
                max, alice, credOffer, userPin, CredentialParameters()
                    .withIssuer(max.did)
                    .withSubject(alice.did)
                    .withTypes(types)
                    .withStatus(CredentialStatus(
                        id = "someId",
                        statusListCredential = "someListCredential",
                        statusListIndex = "1",
                        statusPurpose = "revocation",
                        type =  "StatusList2021Entry"
                    ))
            )
            walletSrv.addCredential(alice, credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationFlow(alice, bob)
            runCatching {
                verificationFlow.verifyPresentationByType(ctype)
            }.onFailure {
                log.error { it }
                it.message shouldContain "is revoked"
            }.onSuccess {
                fail { "Expected revoked credential" }
            }
        }
    }

// Private -------------------------------------------------------------------------------------------------------------

    /**
     * This flow allows us to issue (invalid) credentials that the Verifier cannot accept
     *
     * @See CredentialIssuanceFlow.credentialFromOfferPreAuthorized
     */
    private suspend fun issueCredentialFromParameters(
        issuerCtx: OIDContext,
        holderCtx: OIDContext,
        credOffer: CredentialOfferDraft11,
        userPin: String,
        vcp: CredentialParameters,
    ): CredentialResponse {

        val metadata = issuerSrv.getIssuerMetadata(issuerCtx)
        issuerCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
        holderCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)

        // The Holder received a CredentialOffer
        //
        walletSrv.addCredentialOffer(holderCtx, credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSrv.createTokenRequestPreAuthorized(holderCtx, credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = AuthService.handleTokenRequestPreAuthorized(issuerCtx, tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.getTypes()
        val credReq = walletSrv.createCredentialRequest(holderCtx, types, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val credRes = issuerSrv.getCredentialFromParameters(issuerCtx, vcp)

        return credRes
    }
}
