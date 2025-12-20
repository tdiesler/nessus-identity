package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.config.User
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.CredentialResponse
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.UserInfo
import io.nessus.identity.utils.http
import java.net.URI

abstract class AbstractIssuerService(override val endpointUri: String) : IssuerService {

    val log = KotlinLogging.logger {}

    override fun getAuthorizationMetadataUrl(): String {
        val metadataUrl = "$endpointUri/$WELL_KNOWN_OPENID_CONFIGURATION"
        return metadataUrl
    }

    override suspend fun getAuthorizationMetadata(): AuthorizationMetadata {
        return getIssuerMetadata().getAuthorizationMetadata()
    }

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$endpointUri/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER"
        return metadataUrl
    }

    override suspend fun getIssuerMetadata(): IssuerMetadata {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        log.info { "IssuerMetadataUrl: $metadataUrl" }
        return http.get(metadataUrl).body<IssuerMetadata>()
    }

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {
        error("Not implemented")
    }

    override suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): String {
        error("Not implemented")
    }

    override suspend fun getDeferredCredential(
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse {
        error("Not implemented")
    }

    override suspend fun getCredentialFromRequest(
        credReq: CredentialRequest, accessTokenJwt: SignedJWT, deferred: Boolean
    ): CredentialResponse {
        error("Not implemented")
    }

    // UserAccess ------------------------------------------------------------------------------------------------------

    override fun findUser(predicate: (UserInfo) -> Boolean): UserInfo? {
        error("Not implemented")
    }

    override fun findUserByEmail(email: String): UserInfo? {
        error("Not implemented")
    }

    override fun getUsers(): List<UserInfo> {
        error("Not implemented")
    }

    override fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserInfo {
        error("Not implemented")
    }

    override fun deleteUser(userId: String) {
        error("Not implemented")
    }
}