package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService


class KeycloakIssuerServiceTest : AbstractIssuerServiceTest() {

    override fun createIssuerService(): IssuerService {
        return IssuerService.createKeycloak()
    }
}