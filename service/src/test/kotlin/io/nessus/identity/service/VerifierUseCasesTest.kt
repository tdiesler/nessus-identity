package io.nessus.identity.service

import id.walt.oid4vc.responses.CredentialResponse
import io.kotest.matchers.string.shouldContain
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.flow.CredentialIssuanceEbsi32
import io.nessus.identity.flow.CredentialVerificationEbsi32
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialStatus
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.time.Instant

class VerifierUseCasesTest : AbstractServiceTest() {

    lateinit var issuerSvc: IssuerServiceEbsi32
    lateinit var walletSvc: WalletServiceEbsi32
    lateinit var authSvc: AuthServiceEbsi32

    lateinit var max: OIDContext
    lateinit var alice: OIDContext
    lateinit var bob: OIDContext

    @BeforeEach
    fun setUp() {
        runBlocking {
            // Create the Issuer's OIDC context (Max is the Issuer)
            max = OIDContext(login(Max).withDidInfo())
            issuerSvc = IssuerService.createEbsi(max)

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(login(Alice).withDidInfo())
            walletSvc = WalletService.createEbsi(alice)

            // Create the Verifier's OIDC context (Bob is the Verifier)
            bob = OIDContext(login(Bob).withDidInfo())
            authSvc = AuthServiceEbsi32.create(bob)
        }
    }

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

            // The Holder sends an AuthorizationRequest to the Verifier
            //
            val redirectUri = "$authEndpointUri/${alice.targetId}"
            val authRequest = AuthorizationRequestBuilder()
                .withClientId(alice.did)
                .withRedirectUri(redirectUri)
                .build()

            // The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
            //
            authSvc.validateAuthorizationRequest(authRequest)
            val idTokenRequestJwt = authSvc.buildIDTokenRequest(authRequest)
            val idTokenRedirectUrl = authSvc.buildIDTokenRedirectUrl(idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = walletSvc.createIDToken(urlQueryToMap(idTokenRedirectUrl))

            // Verifier validates the IDToken
            //
            authSvc.validateIDToken(idTokenJwt)
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

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(alice.did, types)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val issuanceFlow = CredentialIssuanceEbsi32(alice, max)
            val credRes = issuanceFlow.credentialFromOfferInTime(credOffer)
            walletSvc.addCredential(credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationEbsi32(alice, bob)
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

            val userPin = "1234"

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(alice.did, types, userPin)

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
            walletSvc.addCredential(credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationEbsi32(alice, bob)
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

            val userPin = "1234"

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(alice.did, types, userPin)

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
            walletSvc.addCredential(credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationEbsi32(alice, bob)
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

            val userPin = "1234"

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(alice.did, types, userPin)

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
            walletSvc.addCredential(credRes)

            // Holder finds Credential by Type and presents it to the Verifier
            //
            val verificationFlow = CredentialVerificationEbsi32(alice, bob)
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
     * @See CredentialIssuanceEbsi32.credentialFromOfferPreAuthorized
     */
    private suspend fun issueCredentialFromParameters(
        issuerCtx: OIDContext,
        holderCtx: OIDContext,
        credOffer: CredentialOfferDraft11,
        userPin: String,
        vcp: CredentialParameters,
    ): CredentialResponse {

        val metadata = issuerSvc.getIssuerMetadata()
        issuerCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
        holderCtx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)

        // The Holder received a CredentialOffer
        //
        walletSvc.addCredentialOffer(credOffer)

        // Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
        //
        val tokenReq = walletSvc.createTokenRequestPreAuthorized(credOffer, userPin)

        // Issuer validates the TokenRequest and responds with an AccessToken
        //
        val accessTokenRes = authSvc.handleTokenRequestPreAuthorized(tokenReq)

        // Holder sends the CredentialRequest using the AccessToken
        //
        val types = credOffer.getTypes()
        val credReq = walletSvc.createCredentialRequest(types, accessTokenRes)

        // Issuer sends the requested Credential
        //
        val credRes = issuerSvc.getCredentialFromParameters(vcp)

        return credRes
    }
}
