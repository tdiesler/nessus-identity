package io.nessus.identity.minisrv

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.service.WalletService
import kotlinx.serialization.json.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.Ignore

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}
    val jsonPretty = Json { prettyPrint = true }

    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService

    abstract suspend fun createIssuerService(): IssuerService

    @BeforeAll
    fun setUp() {
        runBlocking {
            issuerSvc = createIssuerService()
            walletSvc = WalletService.createNative()
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
            val credConfigId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId)
            credOffer.shouldNotBeNull()
        }
    }

    @Test
    fun createCredentialOfferPreAuthorized() {
        runBlocking {
            val credConfigId = "CTWalletSamePreAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId, preAuthorized = true, targetUser = Alice)
            credOffer.shouldNotBeNull()
        }
    }

    @Test
    @Ignore
    fun getCredentialAuthorisedInTime() {
        runBlocking {
            val credConfigId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId, preAuthorized = true, targetUser = Alice)
            credOffer.shouldNotBeNull()
        }
    }
}
