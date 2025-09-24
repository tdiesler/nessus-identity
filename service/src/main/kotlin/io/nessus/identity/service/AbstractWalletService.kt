package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadata
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
}