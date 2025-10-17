package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.Json
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

    override suspend fun findCredential(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ): WalletCredential? {
        val res = widWalletService.listCredentials(ctx)
            .asSequence()
            .filter { predicate(it) }
            .firstOrNull()
        return res
    }

    override suspend fun findCredentials(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ): List<WalletCredential> {
        val res = widWalletService.findCredentials(ctx, predicate)
        return res
    }

    override suspend fun getCredentialById(
        ctx: LoginContext,
        vcId: String
    ): VCDataJwt? {
        val res = widWalletService.findCredentials(ctx) { it.id == vcId }
            .asSequence()
            .map {
                val jwt = SignedJWT.parse(it.document)
                Json.decodeFromString<VCDataJwt>("${jwt.payload}")
            }.firstOrNull()
        return res
    }

    override suspend fun getCredentialByType(
        ctx: LoginContext,
        ctype: String
    ): VCDataJwt? {
        val res = widWalletService.findCredentials(ctx) { true }
            .asSequence()
            .map {
                val jwt = SignedJWT.parse(it.document)
                Json.decodeFromString<VCDataJwt>("${jwt.payload}")
            }
            .filter { it.types.contains(ctype) }
            .firstOrNull()
        return res
    }

    override suspend fun deleteCredential(
        ctx: LoginContext,
        vcId: String
    ): VCDataJwt? {
        val res = widWalletService.deleteCredential(ctx, vcId)?.let {
            val jwt = SignedJWT.parse(it.document)
            Json.decodeFromString<VCDataJwt>("${jwt.payload}")
        }
        return res
    }

    override suspend fun deleteCredentials(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ) {
        widWalletService.findCredentials(ctx) { predicate(it) }
            .forEach { wc -> widWalletService.deleteCredential(ctx, wc.id) }
    }
}