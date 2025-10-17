package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class WalletServiceKeycloakTest : AbstractServiceTest() {

    lateinit var max: LoginContext
    lateinit var alice: LoginContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            // Create the Issuer's OIDC context (Max is the Issuer)
            max = login(Max).withDidInfo()
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = login(Alice).withDidInfo()
            walletSvc = WalletService.createKeycloak()
        }
    }

    @Test
    fun testIssueCredentialInTime() {
        /*
            Authorization Code Flow
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
        */
        runBlocking {

            val ctype = "oid4vc_identity_credential"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint

            // [TODO #280] Issuer should use the wallet's offer endpoint
            // https://github.com/tdiesler/nessus-identity/issues/280
            val credOffer = issuerSvc.createCredentialOffer(max,alice.did, listOf(ctype))
            credOffer.credentialConfigurationIds shouldContain ctype

            val redirectUri = "urn:ietf:wg:oauth:2.0:oob"
            val authContext = walletSvc.authContextForCredential(alice, redirectUri, credOffer)

            val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
            val authCode = callbackHandler.getAuthCode(authContext.authRequestUrl)

            val vcJwt = walletSvc.credentialFromOfferInTime(authContext.withAuthCode(authCode)) as VCDataV11Jwt
            vcJwt.types shouldBeEqual credOffer.credentialConfigurationIds

            val subject = vcJwt.vc.credentialSubject
            subject.claims.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email

            // [TODO #302] Keycloak issues oid4vc_identity_credential with no id value
            // https://github.com/tdiesler/nessus-identity/issues/302
            //subject.id!! shouldBeEqual alice.did
        }
    }

    @Test
    fun testIssueCredentialInTimeSD() {
        /*
            Authorization Code Flow
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
        */
        runBlocking {

            val ctype = "oid4vc_natural_person"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint

            // [TODO #280] Issuer should use the wallet's offer endpoint
            // https://github.com/tdiesler/nessus-identity/issues/280
            val credOffer = issuerSvc.createCredentialOffer(max,alice.did, listOf(ctype))
            credOffer.credentialConfigurationIds shouldContain ctype

            val redirectUri = "urn:ietf:wg:oauth:2.0:oob"
            val authContext = walletSvc.authContextForCredential(alice, redirectUri, credOffer)

            val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
            val authCode = callbackHandler.getAuthCode(authContext.authRequestUrl)

            val vcJwt = walletSvc.credentialFromOfferInTime(authContext.withAuthCode(authCode)) as VCDataSdV11Jwt
            vcJwt.types shouldBeEqual credOffer.credentialConfigurationIds
        }
    }
}
