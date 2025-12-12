package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService


class NativeIssuerServiceTest : AbstractIssuerServiceTest() {

    override fun buildMiniServer(): MiniServer {
        val issuerSvc = IssuerService.createNative()
        return MiniServerBuilder().withIssuerService(issuerSvc).build()
    }

    override fun createIssuerService(): IssuerService {
        return IssuerService.createNative()
    }
}