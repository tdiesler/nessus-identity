package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.nessus.identity.LoginCredentials
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.config.User
import io.nessus.identity.service.IssuerService
import org.junit.jupiter.api.Test

class KeycloakWalletServiceTest : AbstractWalletServiceTest() {

    override fun createIssuerService(): IssuerService {
        return IssuerService.createKeycloak()
    }

    override fun getLoginCredentials(user: User): LoginCredentials {
        return LoginCredentials(user.username, user.password)
    }

    @Test
    fun authorizeWithCodeFlow() {
        runBlocking {
            val configId = "CTWalletSameAuthorisedInTime"
            val authCode = walletSvc.authorizeWithCodeFlow(alice,
                credentialIssuer = issuerSvc.endpointUri,
                clientId = walletSvc.defaultClientId,
                configId = configId,
                loginCredentials = LoginCredentials(Alice.username, Alice.password),
            )
            val tokenResponse = walletSvc.getAccessTokenFromCode(alice, authCode)
            verifyTokenResponse(alice, configId, tokenResponse)
       }
    }

    @Test
    fun authorizeWithDirectAccess() {
        runBlocking {
            val configId = "CTWalletSameAuthorisedInTime"
            val tokenResponse = walletSvc.authorizeWithDirectAccess(alice,
                credentialIssuer = issuerSvc.endpointUri,
                clientId = walletSvc.defaultClientId,
                configId = configId,
                loginCredentials = LoginCredentials(Alice.username, Alice.password),
            )
            verifyTokenResponse(alice, configId, tokenResponse)
        }
    }
}
