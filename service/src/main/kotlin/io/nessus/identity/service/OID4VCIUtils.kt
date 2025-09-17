package io.nessus.identity.service

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.nessus.identity.types.IssuerMetadata

object OID4VCIUtils {
    suspend fun resolveIssuerMetadata(issuerUrl: String): IssuerMetadata {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http.get(issuerMetadataUrl).bodyAsText().let {
            IssuerMetadata.fromJson(it)
        }
    }
}