package io.nessus.identity.service

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.types.IssuerMetadata

object OID4VCIUtils {
    suspend inline fun <reified IMType : IssuerMetadata> resolveIssuerMetadata(issuerUrl: String): IMType {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http.get(issuerMetadataUrl).body<IMType>()
    }
}