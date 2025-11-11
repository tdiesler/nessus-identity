package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.nessus.identity.waltid.Alice
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.Ignore


class IssuerServiceKeycloakTest : AbstractServiceTest() {

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
            metadataUrl.shouldContain("/.well-known/openid-credential-issuer")

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

            issuerSvc.createCredentialOffer(alice.did, listOf("oid4vc_natural_person"))

            assertThrows<IllegalArgumentException> {
                issuerSvc.createCredentialOffer(alice.did, listOf("oid4vc_unknown"))
            }
        }
    }

    @Test
    @Ignore
    fun testCreateCredentialOfferKeycloak() {
        /*
            Credential Offer Endpoint
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        */
        runBlocking {
            issuerSvc.createCredentialOfferKeycloak("oid4vc_natural_person")
        }
    }

    @Test
    fun testGetRealmUsers() {

        val realmUsers = issuerSvc.getUsers()
        realmUsers.forEach { usr ->
            val did = usr.attributes?.get("did")?.firstOrNull()
            log.info { "id=${usr.id}, name=${usr.firstName} ${usr.lastName}, username=${usr.username}, email=${usr.email}, did=$did" }
        }
    }
}