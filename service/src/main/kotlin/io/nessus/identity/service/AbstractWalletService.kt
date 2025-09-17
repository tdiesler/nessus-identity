package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractWalletService<COType: CredentialOffer> : WalletService<COType> {

    val log = KotlinLogging.logger {}

    override suspend fun resolveIssuerMetadata(ctx: OIDContext, issuerUrl: String): IssuerMetadata {
        val metadata = ctx.getAttachment(ISSUER_METADATA_ATTACHMENT_KEY) ?: let {
            val metadata = OID4VCIUtils.resolveIssuerMetadata(issuerUrl)
            log.info { "Issuer Metadata: ${metadata.toJson()}" }
            ctx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
            metadata
        }
        return metadata
    }

}