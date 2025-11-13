package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class VerifierServiceKeycloakTest : AbstractServiceTest() {

    lateinit var alice: OIDContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak
    lateinit var walletAuthSvc: WalletAuthService
    lateinit var verifierSvc: VerifierServiceKeycloak

    @BeforeEach
    fun setUp() {
        runBlocking {
            issuerSvc = IssuerService.createKeycloak()
            verifierSvc = VerifierService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(loginOrRegister(Alice).withDidInfo())
            walletSvc = WalletService.createKeycloak()
            walletAuthSvc = WalletAuthService(walletSvc)
        }
    }

    @Test
    fun requestCredentialPresentation() {
        val ctype = "oid4vc_identity_credential"
        runBlocking {

            // Create the Identity Credential on demand
            val vcJwt = walletSvc.getCredentialByType(alice, ctype)
            if (vcJwt == null) {
                val credOffer = issuerSvc.createCredentialOffer(alice, ctype)
                val authContext = walletSvc.createAuthorizationContext(alice).withCredentialOffer(credOffer)
                val authCode = walletSvc.getAuthorizationCode(authContext, Alice.username, Alice.password)
                val accessToken = walletSvc.getAccessTokenFromCode(authContext, authCode)
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
                        "vct_values": [ "$ctype" ]
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
            val vpcJwt = VCDataV11Jwt.fromEncoded(vpCred)

            val vcp = CredentialParameters()
                .withSubject(alice.did)
                .withTypes(listOf(ctype))

            verifierSvc.validateVerifiableCredential(vpcJwt, vcp)
        }
    }

    @Test
    fun requestCredentialPresentationSD() {
        val ctype = "oid4vc_natural_person"
        runBlocking {

            // Create the Identity Credential on demand
            val vcJwt = walletSvc.getCredentialByType(alice, ctype)
            if (vcJwt == null) {
                val credOffer = issuerSvc.createCredentialOffer(alice, ctype)
                val authContext = walletSvc.createAuthorizationContext(alice).withCredentialOffer(credOffer)
                val authCode = walletSvc.getAuthorizationCode(authContext, Alice.username, Alice.password)
                val accessToken = walletSvc.getAccessTokenFromCode(authContext, authCode)
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
                        "vct_values": [ "$ctype" ]
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
            val vpcJwt = VCDataJwt.fromEncoded(vpCred)

            val vcp = CredentialParameters()
                .withSubject(alice.did)
                .withTypes(listOf(ctype))

            // [TODO #318] Consolidate presented credential verification in verifier
            // https://github.com/tdiesler/nessus-identity/issues/318
            if (vpcJwt is VCDataV11Jwt)
                verifierSvc.validateVerifiableCredential(vpcJwt, vcp)
        }
    }
}
