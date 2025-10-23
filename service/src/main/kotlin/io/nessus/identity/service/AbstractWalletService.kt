package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService

abstract class AbstractWalletService<COType: CredentialOffer>() : WalletService<COType> {

    val log = KotlinLogging.logger {}

    override fun addCredentialOffer(ctx: LoginContext, credOffer: COType): String {
        val credOfferId = ctx.addCredentialOffer(credOffer)
        log.info { "Added CredentialOffer: $credOfferId => ${credOffer.toJson()}" }
        return credOfferId
    }

    @Suppress("UNCHECKED_CAST")
    override fun getCredentialOffers(ctx: LoginContext): Map<String, COType> {
        return ctx.getCredentialOffers().mapValues { (_, v) -> v as COType }
    }

    @Suppress("UNCHECKED_CAST")
    override fun getCredentialOffer(ctx: LoginContext, offerId: String): COType? {
        return ctx.getCredentialOffer(offerId) as? COType
    }

    @Suppress("UNCHECKED_CAST")
    override fun deleteCredentialOffer(ctx: LoginContext, offerId: String): COType? {
        return ctx.deleteCredentialOffer(offerId) as? COType
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
                VCDataJwt.fromEncoded(it.document)
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
                VCDataJwt.fromEncoded(it.document)
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
            VCDataJwt.fromEncoded(it.document)
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