package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataDraft17
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
abstract class AbstractWalletService<COType: CredentialOffer>(val ctx: OIDContext) : WalletService<COType> {

    val log = KotlinLogging.logger {}

    protected val credOfferRegistry = mutableMapOf<String, COType>()

    override fun addCredentialOffer(credOffer: COType): String {
        val credOfferId = "${Uuid.random()}"
        credOfferRegistry[credOfferId] = credOffer
        log.info { "Added CredentialOffer: $credOfferId => ${credOffer.toJson()}" }
        return credOfferId
    }

    @Suppress("UNCHECKED_CAST")
    fun getCredentialOffers(): List<COType> {
        val offers = credOfferRegistry.values.toList()
        return offers
    }

    fun getCredentialOfferById(credOfferId: String): COType? {
        return credOfferRegistry[credOfferId]
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun <IMType: IssuerMetadata> resolveIssuerMetadata(credOffer: CredentialOffer): IMType {
        val metadata = ctx.getAttachment(ISSUER_METADATA_ATTACHMENT_KEY) ?: let {
            val metadata = when (credOffer) {
                is CredentialOfferDraft11 -> credOffer.resolveIssuerMetadata() as IssuerMetadataDraft11
                is CredentialOfferDraft17 -> credOffer.resolveIssuerMetadata() as IssuerMetadataDraft17
                else -> throw IllegalArgumentException("Unsupported CredentialOffer type")
            }
            ctx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
            log.info { "Issuer Metadata: ${metadata.toJson()}" }
            metadata
        }
        return metadata as IMType
    }
}