package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata
import java.time.Instant

abstract class AbstractIssuerService<IMType: IssuerMetadata, COType: CredentialOffer>(
    val issuerUrl: String,
) : IssuerService<IMType, COType> {

    val log = KotlinLogging.logger {}

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }
}