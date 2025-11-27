package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.config.User
import io.nessus.identity.types.IssuerMetadata
import org.keycloak.representations.idm.UserRepresentation

// IssuerService =======================================================================================================

interface IssuerService {

    val issuerEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/issuer"
            else -> requireIssuerConfig().baseUrl
        }

    companion object {

        const val KNOWN_ISSUER_EBSI_V3 = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"

        fun create(): IssuerService {
            return when(Features.getProfile()) {
                EBSI_V32 -> createEbsi()
                else -> createKeycloak()
            }
        }

        fun createEbsi(): IssuerService {
            return IssuerServiceEbsi32();
        }

        fun createKeycloak(): IssuerService {
            val issuerCfg = requireIssuerConfig()
            return IssuerServiceKeycloak(issuerCfg);
        }
    }

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     */
    suspend fun getIssuerMetadata(): IssuerMetadata

    /**
     * Creates a CredentialOfferUri for the given credential configuration id
     */
    suspend fun createCredentialOfferUri(
        configId: String,
        preAuthorized: Boolean = false,
        holder: User? = null,
    ): String

    /**
     * Get registered users
     */
    fun getUsers(): List<UserInfo>

    /**
     * Find a user by email
     */
    fun findUser(predicate: (UserInfo) -> Boolean): UserInfo?

    /**
     * Find a user by email
     */
    fun findUserByEmail(email: String): UserInfo?

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

    data class UserInfo(
        val id: String,
        val did: String?,
        val firstName: String,
        val lastName: String,
        val email: String,
        val username: String,
    ) {
        companion object {
            fun fromUserRepresentation(usr: UserRepresentation) : UserInfo {
                val did = usr.attributes?.get("did")?.firstOrNull()
                return UserInfo(usr.id, did, usr.firstName, usr.lastName, usr.email, usr.username)
            }
        }
    }
}
