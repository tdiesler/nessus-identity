package io.nessus.identity.openapi.issuer

import io.ktor.client.request.*
import io.ktor.http.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.service.http
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.waltid.handleResponse

// IssuerAPIClient ====================================================================================================

class IssuerApiClient: IssuerApi {

    val baseUrl: String

    init {
        val issuerApi = ConfigProvider.requireIssuerApiConfig()
        baseUrl = issuerApi.baseUrl
    }

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
