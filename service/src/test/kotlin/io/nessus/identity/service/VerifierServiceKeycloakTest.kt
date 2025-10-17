package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class VerifierServiceKeycloakTest : AbstractServiceTest() {

    lateinit var max: LoginContext
    lateinit var alice: OIDContext
    lateinit var bob: OIDContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak
    lateinit var walletAuthSvc: WalletAuthService
    lateinit var verifierSvc: VerifierServiceKeycloak

    @BeforeEach
    fun setUp() {
        runBlocking {
            // Create the Issuer's OIDC context (Max is the Issuer)
            max = login(Max).withDidInfo()
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(loginOrRegister(Alice).withDidInfo())
            walletSvc = WalletService.createKeycloak()
            walletAuthSvc = WalletAuthService(walletSvc)

            // Create the Verifier's OIDC context (Bob is the Verifier)
            bob = OIDContext(loginOrRegister(Bob).withDidInfo())
            verifierSvc = VerifierService.createKeycloak()
        }
    }

    @Test
    fun verifyByCredentialType() {
        val ctype = "oid4vc_identity_credential"
        runBlocking {

            // Create the Identity Credential on demand
            val vcJwt = walletSvc.getCredentialByType(alice, ctype)
            if (vcJwt == null) {
                val credOffer = issuerSvc.createCredentialOffer(max, alice.did, listOf(ctype))
                val authContext = walletSvc.authContextForCredential(alice, "urn:ietf:wg:oauth:2.0:oob", credOffer)
                val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
                val authCode = callbackHandler.getAuthCode(authContext.authRequestUrl)
                walletSvc.credentialFromOfferInTime(authContext.withAuthCode(authCode))
            }

            val authContext = verifierSvc.authContextForPresentation(
                ctx = bob,
                clientId = "oid4vcp",
                redirectUri = "urn:ietf:wg:oauth:2.0:oob",
                dcql = DCQLQuery.fromJson("""
                {
                  "credentials": [
                    {
                      "id": "queryId",
                      "format": "jwt_vc",
                      "meta": {
                        "vct_values": [ "oid4vc_identity_credential" ]
                      },
                      "claims": [
                          {"path": ["email"], "values": ["alice@email.com"]}
                      ]
                    }
                  ]
                }                    
                """.trimIndent())
            )
            log.info { authContext.authRequest.toHttpParameters() }

            val authRes = walletAuthSvc.authenticate(alice,authContext.authRequest)
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
}
