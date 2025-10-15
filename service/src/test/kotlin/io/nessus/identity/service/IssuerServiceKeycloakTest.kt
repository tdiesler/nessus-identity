package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows


class IssuerServiceKeycloakTest : AbstractServiceTest() {

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
    fun testGetIssuerMetadata() {
        /*
            Credential Issuer Metadata
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

            Issuer Metadata Endpoints
            https://oauth.localtest.me/realms/oid4vci/.well-known/openid-configuration
            https://oauth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
        */
        runBlocking {

            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    fun testCreateCredentialOffer() {
        /*
            Credential Offer Endpoint
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        */
        runBlocking {

            issuerSvc.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))

            assertThrows<IllegalArgumentException> {
                issuerSvc.createCredentialOffer(max, alice.did, listOf("oid4vc_unknown"))
            }
        }
    }

    @Test
    fun testGetRealmUsers() {

        val realmUsers = issuerSvc.getRealmUsers()
        realmUsers.forEach { usr ->
            val did = usr.attributes?.get("did")?.firstOrNull()
            log.info { "id=${usr.id}, name=${usr.firstName} ${usr.lastName}, username=${usr.username}, email=${usr.email}, did=$did" }
        }
    }
}