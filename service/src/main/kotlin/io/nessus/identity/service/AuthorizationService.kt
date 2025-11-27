package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationMetadata

// AuthorizationService ================================================================================================

interface AuthorizationService: ExperimentalAuthorizationService, LegacyAuthorizationService {

    fun buildAuthorizationMetadata(targetUri: String): AuthorizationMetadata

    companion object {
        fun create(): AuthorizationService {
            return NativeAuthorizationService()
        }
    }
}