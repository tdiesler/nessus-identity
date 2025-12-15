package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.nessus.identity.OAuthClient
import io.nessus.identity.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.config.User
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferUri
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.OfferUriType
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.UserInfo
import io.nessus.identity.utils.http
import jakarta.ws.rs.core.HttpHeaders
import kotlinx.serialization.json.*
import org.keycloak.OAuth2Constants
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation

class KeycloakIssuerService(val config: IssuerConfig): AbstractIssuerService(
    endpointUri = "${config.baseUrl}/realms/${config.realm}"
) {

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {

        val credOfferUriRes = createCredentialOfferUriInternal(configId, preAuthorized, targetUser, OfferUriType.URI)

        val credOfferUriJson = handleApiResponse(credOfferUriRes) as JsonObject
        val issuerUrl = credOfferUriJson.getValue("issuer").jsonPrimitive.content
        val nonce = credOfferUriJson.getValue("nonce").jsonPrimitive.content

        val credOfferUri = "$issuerUrl$nonce"

        val credOfferRes = http.get(credOfferUri)
        val credOffer = (handleApiResponse(credOfferRes) as CredentialOfferV0)
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    override suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): String {

        val credOfferUriRes = createCredentialOfferUriInternal(configId, preAuthorized, targetUser, OfferUriType.URI)

        val credOfferUriJson = handleApiResponse(credOfferUriRes) as JsonObject
        val issuerUrl = credOfferUriJson.getValue("issuer").jsonPrimitive.content
        val nonce = credOfferUriJson.getValue("nonce").jsonPrimitive.content

        val credOfferUri = "$issuerUrl$nonce"
        log.info { "CredentialOfferUri: $credOfferUri" }

        return credOfferUri
    }

    /**
     * Creates a CredentialOfferUri QR Code
     */
    suspend fun createCredentialOfferUriQRCode(
        configId: String,
        preAuthorized: Boolean = false,
        holder: User? = null,
    ): ByteArray {

        val credOfferUriRes = createCredentialOfferUriInternal(
            configId,
            preAuthorized,
            holder,
            OfferUriType.QR_CODE
        )

        return handleApiResponse(credOfferUriRes) as ByteArray
    }

    // ExperimentalIssuerService ---------------------------------------------------------------------------------------

    // UserAccess ------------------------------------------------------------------------------------------------------

    override fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserInfo {
        val realm = config.realm as String
        val user = UserRepresentation().apply {
            this.username = username
            this.email = email
            this.firstName = firstName
            this.lastName = lastName
            this.isEnabled = true
            this.isEmailVerified = true
        }

        keycloakConnect(realm).use { keycloak ->
            val users = keycloak.realm(realm).users()
            val res = users.create(user)
            if (res.status != 201) {
                error("Failed to create user: ${res.statusInfo.reasonPhrase}")
            }
            val userId = res.location.path.substringAfterLast('/')
            log.info { "Created user with ID: $userId" }

            val credential = CredentialRepresentation().apply {
                type = CredentialRepresentation.PASSWORD
                value = password
                isTemporary = false
            }

            val user = users.get(userId)
            user.resetPassword(credential)

            return UserInfo.fromUserRepresentation(user.toRepresentation())
        }
    }

    override fun deleteUser(userId: String) {
        val realm = config.realm as String
        keycloakConnect(realm).use {
            it.realm(realm).users().delete(userId)
        }
    }

    override fun findUser(predicate: (UserInfo) -> Boolean): UserInfo? {
        val userInfo = getUsers().firstOrNull { predicate(it) }
        return userInfo
    }

    override fun findUserByEmail(email: String): UserInfo? {
        val userInfo = findUser { it.email == email }
        return userInfo
    }

    override fun getUsers(): List<UserInfo> {
        val realm = config.realm as String
        val uerInfos = keycloakConnect(realm).use { kc ->
            val usersResource = kc.realm(realm).users()
            usersResource.list().map { UserInfo.fromUserRepresentation(it) }
        }
        return uerInfos
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun createCredentialOfferUriInternal(
        configId: String,
        preAuthorized: Boolean,
        targetUser: User?,
        type: OfferUriType?,
    ): HttpResponse {

        val issuerMetadata = getIssuerMetadata()
        val scope = requireNotNull(issuerMetadata.getCredentialScope(configId))
        { "No credential scope for: $configId" }

        val cfg = requireIssuerConfig()

        val adminUser = config.adminUser
        val tokReq = TokenRequest.DirectAccess(
            clientId = cfg.clientId as String,
            username = adminUser.username,
            password = adminUser.password,
            scopes = listOf(scope)
        )

        val tokenEndpointUri = getAuthorizationMetadata().getAuthorizationTokenEndpointUri()
        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUri, tokReq)
        val accessToken = tokRes.accessToken

        val tokenJwt = SignedJWT.parse(accessToken)
        log.info { "AccessToken: ${tokenJwt.jwtClaimsSet}" }

        val params = CredentialOfferUri(configId).withPreAuthorized(preAuthorized)
        targetUser?.also { params.withTargetUser(it.username) }
        type?.also { params.withType(it) }

        val credOfferUriUrl = "$endpointUri/protocol/oid4vc/credential-offer-uri"
        log.info { "CredentialOfferUriReq: $credOfferUriUrl?${params.getUrlQuery()}" }
        val credOfferUriRes = http.get(credOfferUriUrl) {
            header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
            url {
                params.parameters().forEach { (k, v) ->
                    parameter(k, v)
                }
            }
        }
        return credOfferUriRes
    }

    private fun keycloakConnect(realm: String): Keycloak {
        val kc = KeycloakBuilder.builder()
            .serverUrl(config.baseUrl)
            .clientId(config.serviceId)
            .clientSecret(config.serviceSecret)
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .realm(realm)
            .build()
        log.info { "Connected to Keycloak realm: $realm" }
        return kc
    }
}