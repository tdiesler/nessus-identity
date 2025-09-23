package io.nessus.identity.openapi

import io.ktor.client.request.*
import io.ktor.http.*
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.waltid.handleResponse
import io.nessus.identity.waltid.http

// IssuerAPIClient ====================================================================================================

class IssuerApiClient: IssuerApi {

    val baseUrl = "http://localhost:8081"

    /**
     * Receives a CredentialOffer for the given walletId.
     */
    override suspend fun createCredentialOffer(
        subjectId: String,
        credentialConfigurationIds: List<String>,
    ): CredentialOffer {
        val res = http.get("$baseUrl/issuer/credential-offer") {
            contentType(ContentType.Application.Json)
            parameter("subject_id", subjectId)
            credentialConfigurationIds.forEach {
                parameter("credential_configuration_id", it)
            }
        }
        return handleResponse<CredentialOffer>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
