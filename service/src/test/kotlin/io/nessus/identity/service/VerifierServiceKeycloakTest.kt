package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class VerifierServiceKeycloakTest : AbstractServiceTest() {

    lateinit var max: LoginContext
    lateinit var alice: OIDContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak
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

            verifierSvc = VerifierService.createKeycloak()
        }
    }

    @Test
    fun verifyByCredentialType() {
        val ctype = "oid4vc_identity_credential"
        runBlocking {

            // Create the Identity Credential on demand
            val vcJwt = walletSvc.findCredential(alice) { it.containsType(ctype) }
            if (vcJwt == null) {
                val credOffer = issuerSvc.createCredentialOffer(max, alice.did, listOf(ctype))
                val authContext = walletSvc.authorizationContextFromOffer(alice, "urn:ietf:wg:oauth:2.0:oob", credOffer)
                val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
                val authCode = callbackHandler.getAuthCode(authContext.authRequestUrl)
                walletSvc.credentialFromOfferInTime(authContext.withAuthCode(authCode))
            }
        }
    }
}
