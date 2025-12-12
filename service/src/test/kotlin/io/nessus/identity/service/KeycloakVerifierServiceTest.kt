package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.types.CredentialMatcher
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.types.W3CCredentialValidator.validateVerifiableCredential
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class KeycloakVerifierServiceTest : AbstractServiceTest() {

    lateinit var alice: LoginContext

    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService
    lateinit var verifierSvc: VerifierService

    @BeforeEach
    fun setUp() {
        runBlocking {
            issuerSvc = IssuerService.createKeycloak()
            verifierSvc = VerifierService.createNative()

            // Create the Holders's LoginContext (Alice is the Holder)
            alice = LoginContext.loginOrRegister(Alice).withDidInfo()
            walletSvc = WalletService.createNative()
        }
    }

    @Test
    fun requestCredentialPresentation() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person_jwt"

            val issuerMetadata = issuerSvc.getIssuerMetadata()
            val ctype = issuerMetadata.getCredentialScope(credConfigId)

            // Create the Identity Credential on demand
            val credJwt = walletSvc.getCredentialByType(alice, ctype!!)
            if (credJwt == null) {
                val offerUri = issuerSvc.createCredentialOfferUri(credConfigId, preAuthorized = true, targetUser = Alice)
                val credOffer = walletSvc.getCredentialOfferFromUri(offerUri)
                val accessToken = walletSvc.authorizeFromCredentialOffer(alice, credOffer)
                walletSvc.getCredential(alice, accessToken)
            }

            val authReq = verifierSvc.buildAuthorizationRequestForPresentation(
                clientId = "oid4vcp",
                redirectUri = "urn:ietf:wg:oauth:2.0:oob",
                dcql = DCQLQuery.fromJson("""
                {
                  "credentials": [
                    {
                      "id": "queryId",
                      "format": "jwt_vc",
                      "meta": {
                        "vct_values": [ "$credConfigId" ]
                      },
                      "claims": [
                          {"path": ["email"], "values": ["alice@email.com"]}
                      ]
                    }
                  ]
                }                    
                """.trimIndent())
            )

            log.info { authReq.toRequestParameters() }

            val authRes = walletSvc.handleVPTokenRequest(alice, authReq)
            val vpTokenJwt = SignedJWT.parse(authRes.vpToken)

            // Verifier validates the VPToken
            //
            val vpHolder = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.holder").first()
            if (vpHolder != alice.did) error("Unexpected holder id: $vpHolder")

            // Verifier validates the Credential
            //
            val vpCred = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.verifiableCredential").first()
            val vpcJwt = W3CCredentialV11Jwt.fromEncoded(vpCred)

            val vcp = CredentialParameters()
                .withSubject(alice.did)
                .withTypes(listOf(credConfigId))

            validateVerifiableCredential(vpcJwt, vcp)
        }
    }

    @Test
    fun requestCredentialPresentationSD() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person_sd"

            val issuerMetadata = issuerSvc.getIssuerMetadata()
            val ctype = issuerMetadata.getCredentialScope(credConfigId)

            // Create the Identity Credential on demand
            val credJwt = walletSvc.getCredentialByType(alice, ctype!!)
            if (credJwt == null) {
                val offerUri = issuerSvc.createCredentialOfferUri(credConfigId, preAuthorized = true, targetUser = Alice)
                val credOffer = walletSvc.getCredentialOfferFromUri(offerUri)
                walletSvc.getCredentialFromOffer(alice, credOffer)
            }

            val authReq = verifierSvc.buildAuthorizationRequestForPresentation(
                clientId = "oid4vcp",
                redirectUri = "urn:ietf:wg:oauth:2.0:oob",
                dcql = DCQLQuery.fromJson("""
                {
                  "credentials": [
                    {
                      "id": "queryId",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": [ "$credConfigId" ]
                      },
                      "claims": [
                          {"path": ["email"], "values": ["alice@email.com"]}
                      ]
                    }
                  ]
                }                    
                """.trimIndent())
            )

            log.info { authReq.toRequestParameters() }

            val authRes = walletSvc.handleVPTokenRequest(alice, authReq)
            val vpTokenJwt = SignedJWT.parse(authRes.vpToken)

            // Verifier validates the VPToken
            //
            val vpHolder = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.holder").first()
            if (vpHolder != alice.did) error("Unexpected holder id: $vpHolder")

            // Verifier validates the Credential
            //
            val vpCred = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.verifiableCredential").first()
            val vpcJwt = W3CCredentialJwt.fromEncoded(vpCred)

            val vcp = CredentialParameters()
                .withSubject(alice.did)
                .withTypes(listOf(credConfigId))

            // [TODO #318] Consolidate presented credential verification in verifier
            // https://github.com/tdiesler/nessus-identity/issues/318
            if (vpcJwt is W3CCredentialV11Jwt)
                validateVerifiableCredential(vpcJwt, vcp)
        }
    }
}
