package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class VerifierServiceKeycloakTest : AbstractServiceTest() {

    lateinit var alice: OIDContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: DefaultWalletService
    lateinit var walletAuthSvc: WalletAuthorizationService
    lateinit var verifierSvc: DefaultVerifierService

    @BeforeEach
    fun setUp() {
        runBlocking {
            issuerSvc = IssuerService.createKeycloak()
            verifierSvc = VerifierService.create()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(loginOrRegister(Alice).withDidInfo())
            walletSvc = WalletService.create()
            walletAuthSvc = WalletAuthorizationService(walletSvc)
        }
    }

    @Test
    fun requestCredentialPresentation() {
        runBlocking {
            val credConfigId = "oid4vc_identity_credential"

            val issuerMetadata = issuerSvc.getIssuerMetadata()
            val ctype = issuerMetadata.getCredentialScope(credConfigId)

            // Create the Identity Credential on demand
            val credJwt = walletSvc.getCredentialByType(alice, ctype!!)
            if (credJwt == null) {
                val offerUri = issuerSvc.createCredentialOfferUri(Max, credConfigId, true, Alice)
                val credOffer = walletSvc.getCredentialOffer(offerUri)
                val authContext = AuthorizationContext.create(alice)
                val accessToken = walletSvc.getAccessTokenFromCredentialOffer(authContext, credOffer)
                walletSvc.getCredential(authContext, accessToken)
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

            log.info { authReq.getParameters() }

            val authRes = walletAuthSvc.handleVPTokenRequest(alice, authReq)
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

            verifierSvc.validateVerifiableCredential(vpcJwt, vcp)
        }
    }

    @Test
    fun requestCredentialPresentationSD() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"

            val issuerMetadata = issuerSvc.getIssuerMetadata()
            val ctype = issuerMetadata.getCredentialScope(credConfigId)

            // Create the Identity Credential on demand
            val credJwt = walletSvc.getCredentialByType(alice, ctype!!)
            if (credJwt == null) {
                val offerUri = issuerSvc.createCredentialOfferUri(Max, credConfigId, true, Alice)
                val credOffer = walletSvc.getCredentialOffer(offerUri)
                val authContext = AuthorizationContext.create(alice)
                val accessToken = walletSvc.getAccessTokenFromCredentialOffer(authContext, credOffer)
                walletSvc.getCredential(authContext, accessToken)
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

            log.info { authReq.getParameters() }

            val authRes = walletAuthSvc.handleVPTokenRequest(alice, authReq)
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
                verifierSvc.validateVerifiableCredential(vpcJwt, vcp)
        }
    }
}
