package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import kotlinx.serialization.json.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class WalletServiceKeycloakTest : AbstractServiceTest() {

    lateinit var alice: LoginContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = login(Alice).withDidInfo()
            walletSvc = WalletService.createKeycloak()
        }
    }

    /**
     * Issue credential in time (Authorization Code Flow)
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
     */
    @Test
    fun testCredentialFromOfferInTime() {
        runBlocking {
            val ctype = "oid4vc_identity_credential"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint

            val credOffer = issuerSvc.createCredentialOffer(alice, ctype)
            val authContext = walletSvc.createAuthorizationContext(alice).withCredentialOffer(credOffer)
            val authCode = walletSvc.getAuthorizationCode(authContext, Alice.username, Alice.password)
            val accessToken = walletSvc.getAccessTokenFromCode(authContext, authCode)

            val vcJwt = walletSvc.getCredential(authContext, accessToken) as VCDataV11Jwt
            vcJwt.types shouldBeEqual credOffer.credentialConfigurationIds

            val subject = vcJwt.vc.credentialSubject
            subject.claims.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
            subject.id!! shouldBeEqual alice.did
        }
    }

    @Test
    fun testCredentialNoOfferInTime() {
        runBlocking {
            val ctype = "oid4vc_identity_credential"

            val authContext = walletSvc.createAuthorizationContext(alice)
                .withIssuerMetadata(issuerSvc.getIssuerMetadata())
                .withCredentialConfigurationId(ctype)

            val authCode = walletSvc.getAuthorizationCode(authContext, Alice.username, Alice.password)
            val accessToken = walletSvc.getAccessTokenFromCode(authContext, authCode)

            val vcJwt = walletSvc.getCredential(authContext, accessToken) as VCDataV11Jwt
            vcJwt.types shouldBeEqual listOf(ctype)

            val subject = vcJwt.vc.credentialSubject
            subject.claims.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
            subject.id!! shouldBeEqual alice.did
        }
    }

    /**
     * Issue credential in time (Authorization Code Flow)
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
     */
    @Test
    fun testSDCredentialInTime() {
        runBlocking {
            val ctype = "oid4vc_natural_person"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint

            val credOffer = issuerSvc.createCredentialOffer(alice, ctype)
            credOffer.filteredConfigurationIds shouldContain ctype

            val authContext = walletSvc.createAuthorizationContext(alice).withCredentialOffer(credOffer)
            val authCode = walletSvc.getAuthorizationCode(authContext, Alice.username, Alice.password)
            val accessToken = walletSvc.getAccessTokenFromCode(authContext, authCode)

            val vcJwt = walletSvc.getCredential(authContext, accessToken) as VCDataSdV11Jwt
            vcJwt.types shouldBeEqual credOffer.credentialConfigurationIds
            vcJwt.disclosedValue("sub") shouldBeEqual alice.did
        }
    }

    /**
     * Issue credential in time (Authorization Code Flow)
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
     */
    @Test
    fun testSDCredentialPreAuthorized() {
        runBlocking {
            val ctype = "oid4vc_natural_person"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint

            val credOffer = issuerSvc.createCredentialOffer(alice, ctype, true)
            credOffer.filteredConfigurationIds shouldContain ctype

            val authContext = walletSvc.createAuthorizationContext(alice)
            val accessToken = walletSvc.getAccessTokenPreAuthorized(authContext, credOffer)

            val vcJwt = walletSvc.getCredential(authContext, accessToken) as VCDataSdV11Jwt
            vcJwt.types shouldBeEqual credOffer.credentialConfigurationIds
            vcJwt.disclosedValue("sub") shouldBeEqual alice.did
        }
    }
}
