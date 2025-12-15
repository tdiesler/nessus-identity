package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.nessus.identity.service.IssuerService
import org.junit.jupiter.api.Test
import kotlin.test.Ignore

class KeycloakWalletServiceTest : AbstractWalletServiceTest() {

    override fun createIssuerService(): IssuerService {
        return IssuerService.createKeycloak()
    }

    @Test
    @Ignore
    override fun getCredentialAuthorisedInTime() {
        runBlocking {
        }
    }

    @Test
    @Ignore
    override fun getCredentialAuthorisedDeferred() {
        runBlocking {
        }
    }

    @Test
    @Ignore
    override fun getCredentialPreAuthorisedInTime() {
        runBlocking {
        }
    }

    @Test
    @Ignore
    override fun getCredentialPreAuthorisedDeferred() {
        runBlocking {
        }
    }
}
