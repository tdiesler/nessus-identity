package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService


class KeycloakIssuerServiceTest : AbstractServiceTest() {

    override suspend fun createIssuerService(): IssuerService {
        return IssuerService.createKeycloak()
    }
}