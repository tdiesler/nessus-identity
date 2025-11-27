package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.config.ConfigProvider.Alice
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows


class IssuerServiceKeycloakTest : AbstractServiceTest() {

    lateinit var alice: LoginContext

    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = login(Alice).withDidInfo()
            walletSvc = WalletService.create()
        }
    }

    /**
     * Credential Issuer Metadata
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
     */
    @Test
    fun getIssuerMetadata() {
        runBlocking {

            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldContain("/.well-known/openid-credential-issuer")
            metadataUrl.shouldEndWith("/realms/oid4vci")

            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOffer() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"
            val offerUri = issuerSvc.createCredentialOfferUri(credConfigId)
            val credOffer = walletSvc.getCredentialOffer(offerUri)
            credOffer.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOfferQRCode() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"
            val issuerKeycloak = issuerSvc as IssuerServiceKeycloak
            val offerQrCode = issuerKeycloak.createCredentialOfferUriQRCode(credConfigId)
            offerQrCode.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOfferPreAuthorized() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"
            val offerUri = issuerSvc.createCredentialOfferUri(credConfigId, true, Alice)
            val credOffer = walletSvc.getCredentialOffer(offerUri)
            credOffer.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOfferInvalidType() {
        runBlocking {
            assertThrows<IllegalArgumentException> {
                issuerSvc.createCredentialOfferUri("oid4vc_unknown")
            }
        }
    }

    @Test
    fun getRealmUsers() {
        val realmUsers = issuerSvc.getUsers()
        realmUsers.forEach { usr ->
            log.info { "id=${usr.id}, name=${usr.firstName} ${usr.lastName}, username=${usr.username}, email=${usr.email}, did=${usr.did}" }
        }
    }
}