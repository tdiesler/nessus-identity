package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.config.User
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.UserInfo

interface IssuerService: ExperimentalIssuerService {

    /**
     * The endpoint uri for this service
     */
    val endpointUri: String

    companion object {
        const val KNOWN_ISSUER_EBSI_V3 = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
        const val WELL_KNOWN_OPENID_CONFIGURATION = ".well-known/openid-configuration"
        const val WELL_KNOWN_OPENID_CREDENTIAL_ISSUER = ".well-known/openid-credential-issuer"

        fun createEbsi32(): IssuerService {
            return Ebsi32IssuerService()
        }
        fun createNative(): IssuerService {
            val config = if(Features.isProfile(EBSI_V32)) {
                requireIssuerConfig("proxy")
            } else {
                requireIssuerConfig("native")
            }
            return NativeIssuerService(config)
        }
        fun createKeycloak(): IssuerService {
            val config = requireIssuerConfig("keycloak")
            return KeycloakIssuerService(config)
        }
    }

    /**
     * Get the Issuer's authorization metadata Url
     */
    fun getAuthorizationMetadataUrl(): String

    /**
     * Get the Issuer's authorization metadata
     */
    suspend fun getAuthorizationMetadata(): AuthorizationMetadata

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
     */
    suspend fun getIssuerMetadata(): IssuerMetadata

    /**
     * Creates a CredentialOffer for the given credential configuration id
     */
    suspend fun createCredentialOffer(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): CredentialOffer

    /**
     * Creates a CredentialOfferUri for the given credential configuration id
     */
    suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): String

    // UserAccess ------------------------------------------------------------------------------------------------------

    /**
     * Create a new user
     */
    fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserInfo

    /**
     * Delete new user
     */
    fun deleteUser(userId: String)

    /**
     * Find a user by email
     */
    fun findUser(predicate: (UserInfo) -> Boolean): UserInfo?

    /**
     * Find a user by email
     */
    fun findUserByEmail(email: String): UserInfo?

    /**
     * Get registered users
     */
    fun getUsers(): List<UserInfo>
}