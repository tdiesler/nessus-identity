package io.nessus.identity.service

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.config.User
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.UserInfo
import io.nessus.identity.utils.http
import kotlinx.serialization.json.*

class Ebsi32IssuerService : AbstractIssuerService(
    endpointUri = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
) {

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        txCode: String?,
        targetUser: User?,
    ): CredentialOffer {
        val credOfferUriObj = createCredentialOfferUri(configId, clientId, targetUser, preAuthorized, txCode)
        val credOfferUri = credOfferUriObj.getValue("credential_offer_uri").jsonPrimitive.content
        val res = http.get(credOfferUri)
        if (res.status.value !in 200..202) {
            error("Error fetching credential offer: ${res.bodyAsText()}")
        }
        val credOffer = res.body<CredentialOfferDraft11>()
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    override suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String?,
        targetUser: User?,
        preAuthorized: Boolean,
        txCode: String?,
    ): JsonObject {

        val res = http.get("$endpointUri/initiate-credential-offer") {
            url {
                parameters.append("credential_type", configId)
                parameters.append("client_id", requireNotNull(clientId) { "No client_id" })
            }
        }
        log.info { "Initiating CredentialOffer: ${res.request.url}" }

        val redirectUrl = res.headers["location"] ?:
            error("Error creating credential offer uri: ${res.body<String>()}")
        log.info { "CredentialOffer RedirectUrl: $redirectUrl" }

        val credOfferUri = URLBuilder(redirectUrl).build().parameters["credential_offer_uri"] ?:
            error("No credential_offer_uri in: $redirectUrl")
        log.info { "CredentialOfferUri: $credOfferUri" }

        val credOfferUriString = Json.encodeToString(mapOf(Pair("credential_offer_uri", credOfferUri)))
        return Json.decodeFromString<JsonObject>(credOfferUriString)
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