package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerServiceKeycloakTest: AbstractServiceTest() {

    lateinit var issuerSvc: IssuerService

    @BeforeAll
    fun setUp() {
        runBlocking {
            issuerSvc = IssuerService.createKeycloak()
        }
    }

    @Test
    fun getIssuerMetadata() {
        runBlocking {
            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER")
            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOffer() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId)
            credOffer.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOfferPreAuthorized() {
        runBlocking {
            val credConfigId = "oid4vc_natural_person"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId, preAuthorized = true, targetUser = Alice)
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