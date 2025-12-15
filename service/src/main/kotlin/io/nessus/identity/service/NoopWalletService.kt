package io.nessus.identity.service

// NativeWalletService =================================================================================================

class NoopWalletService : AbstractWalletService() {

    override val endpointUri get() = error("Not implemented")
    override val defaultClientId get() = error("Not implemented")
    override val authorizationSvc get() = error("Not implemented")

}