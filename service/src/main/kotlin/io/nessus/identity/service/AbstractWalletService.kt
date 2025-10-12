package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataDraft17
import kotlin.uuid.Uuid

abstract class AbstractWalletService<COType: CredentialOffer>() : WalletService<COType> {

    val log = KotlinLogging.logger {}

    protected val credOfferRegistry = mutableMapOf<String, COType>()

    override fun addCredentialOffer(credOffer: COType): String {
        val credOfferId = "${Uuid.random()}"
        credOfferRegistry[credOfferId] = credOffer
        log.info { "Added CredentialOffer: $credOfferId => ${credOffer.toJson()}" }
        return credOfferId
    }

    @Suppress("UNCHECKED_CAST")
    override fun getCredentialOffers(): Map<String, COType> {
        return credOfferRegistry.toMap()
    }

    override fun getCredentialOffer(offerId: String): COType? {
        return credOfferRegistry[offerId]
    }

    override fun deleteCredentialOffer(offerId: String): COType? {
        return credOfferRegistry.remove(offerId)
    }
}