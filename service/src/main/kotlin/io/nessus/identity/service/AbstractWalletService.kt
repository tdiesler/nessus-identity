package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService

abstract class AbstractWalletService(): WalletService {

    val log = KotlinLogging.logger {}

    override fun addCredentialOffer(ctx: LoginContext, credOffer: CredentialOffer): String {
        val offerId = widWalletService.addCredentialOffer(ctx, credOffer)
        return offerId
    }

    @Suppress("UNCHECKED_CAST")
    override fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOffer> {
        return widWalletService.getCredentialOffers(ctx)
    }

    @Suppress("UNCHECKED_CAST")
    override fun getCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        return widWalletService.getCredentialOffer(ctx, offerId)
    }

    @Suppress("UNCHECKED_CAST")
    override fun deleteCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        return widWalletService.deleteCredentialOffer(ctx, offerId)
    }

    override fun deleteCredentialOffers(ctx: LoginContext, predicate: (CredentialOffer) -> Boolean) {
        getCredentialOffers(ctx)
            .filter { (_, v) -> predicate(v) }
            .forEach { (k, _) -> widWalletService.deleteCredentialOffer(ctx, k) }
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
    ): W3CCredentialJwt? {
        val res = widWalletService.findCredentials(ctx) { it.id == vcId }
            .asSequence()
            .map {
                W3CCredentialJwt.fromEncoded(it.document)
            }.firstOrNull()
        return res
    }

    override suspend fun getCredentialByType(
        ctx: LoginContext,
        ctype: String
    ): W3CCredentialJwt? {
        val res = widWalletService.findCredentials(ctx) { true }
            .asSequence()
            .map {
                W3CCredentialJwt.fromEncoded(it.document)
            }
            .filter { it.types.contains(ctype) }
            .firstOrNull()
        return res
    }

    override suspend fun deleteCredential(
        ctx: LoginContext,
        vcId: String
    ): W3CCredentialJwt? {
        val res = widWalletService.deleteCredential(ctx, vcId)?.let {
            W3CCredentialJwt.fromEncoded(it.document)
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