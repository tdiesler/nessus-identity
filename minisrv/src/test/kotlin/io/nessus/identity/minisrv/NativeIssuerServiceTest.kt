package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService


class NativeIssuerServiceTest : AbstractServiceTest() {

    override suspend fun createIssuerService(): IssuerService {
        return IssuerService.createNative()
    }
}