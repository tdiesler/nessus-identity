package io.nessus.identity.service

// NativeVerifierService ===============================================================================================

class NoopVerifierService : AbstractVerifierService() {

    override val endpointUri get() = error("Not implemented")
    override val authorizationSvc get() = error("Not implemented")
}