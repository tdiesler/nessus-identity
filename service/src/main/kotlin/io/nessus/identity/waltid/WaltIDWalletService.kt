package io.nessus.identity.waltid

import com.nimbusds.jwt.SignedJWT
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import id.walt.oid4vc.data.CredentialFormat
import id.walt.webwallet.db.models.WalletCredential
import id.walt.webwallet.db.models.Wallets
import id.walt.webwallet.service.credentials.CredentialsService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.service.AttachmentKeys.AUTH_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.waltid.CredentialOfferTable.deleteCredentialOffer
import io.nessus.identity.waltid.CredentialOfferTable.insertCredentialOffer
import io.nessus.identity.waltid.CredentialOfferTable.selectCredentialOffer
import io.nessus.identity.waltid.CredentialOfferTable.selectCredentialOffers
import kotlinx.serialization.json.*
import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.dao.id.UUIDTable
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.javatime.timestamp
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.SchemaUtils
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insertAndGetId
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import java.util.*
import javax.sql.DataSource
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant
import kotlin.uuid.Uuid

class WaltIDWalletService {

    val api: WaltIDApiClient

    constructor(apiUrl: String) {
        log.info { "WalletService: $apiUrl" }
        api = WaltIDApiClient(apiUrl)
    }

    companion object {
        val log = KotlinLogging.logger {}

        private val dataSource: Lazy<DataSource> = lazy {
            val cfg = ConfigProvider.requireDatabaseConfig()
            log.info { "Database: ${cfg.jdbcUrl}" }
            HikariDataSource(HikariConfig().apply {
                jdbcUrl = cfg.jdbcUrl
                username = cfg.username
                password = cfg.password
                driverClassName = "org.postgresql.Driver"
                transactionIsolation = "TRANSACTION_SERIALIZABLE"
                maximumPoolSize = 10
                isAutoCommit = false
            })
        }

        private fun <T> withConnection(runThis: () -> T): T {
            if (!dataSource.isInitialized()) {
                Database.connect(dataSource.value)
                transaction {
                    SchemaUtils.create(CredentialOfferTable)
                }
            }
            return runThis()
        }
    }

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun authLogin(params: LoginParams): LoginContext {
        val res = api.authLogin(params.toAuthLoginRequest())
        val ctx = LoginContext().also {
            it.putAttachment(AUTH_TOKEN_ATTACHMENT_KEY, res.token)
        }
        return ctx
    }

    suspend fun authLoginWithWallet(params: LoginParams): LoginContext {
        val ctx = authLogin(params).also {
            val wi = listWallets(it).first()
            it.putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        return ctx
    }

    suspend fun authLogout(): Boolean {
        return api.authLogout()
    }

    suspend fun authRegister(params: RegisterUserParams): String {
        return api.authRegister(params.toAuthRegisterRequest()).trim()
    }

    suspend fun authUserInfo(token: String): UserInfo? {
        return api.authUserInfo(token)
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun findWallet(ctx: LoginContext, predicate: suspend (WalletInfo) -> Boolean): WalletInfo? {
        return api.accountWallets(ctx).wallets.firstOrNull { predicate(it) }
    }

    suspend fun findWalletByDid(ctx: LoginContext, did: String): WalletInfo? {
        return findWallet(ctx) { w -> listDids(ctx).any { it.did == did } }
    }

    suspend fun findWalletById(ctx: LoginContext, id: String): WalletInfo? {
        return findWallet(ctx) { w -> w.id == id }
    }

    suspend fun listWallets(ctx: LoginContext): List<WalletInfo> {
        val res = api.accountWallets(ctx)
        return res.wallets.toList()
    }

    // Credentials -----------------------------------------------------------------------------------------------------

    fun addCredential(walletId: String, format: CredentialFormat, sigJwt: SignedJWT): String {

        val vcJwt = VCDataJwt.fromEncoded("${sigJwt.serialize()}")
        val walletUid = Uuid.parse(walletId)
        val document = sigJwt.serialize()

        val vcId = vcJwt.vcId

        val walletCredential = WalletCredential(
            id = vcId,
            format = format,
            wallet = walletUid,
            document = document,
            addedOn = Clock.System.now(),
            disclosures = null,
            deletedOn = null,
        )

        log.info { "Adding WalletCredential: ${Json.encodeToString(walletCredential)}" }
        withConnection {
            CredentialsService().add(walletUid, walletCredential)
            log.info { "Added WalletCredential: $vcId" }
        }
        return vcId
    }

    suspend fun listCredentials(ctx: LoginContext): List<WalletCredential> {
        val res = findCredentials(ctx) { true }
        return res
    }

    suspend fun findCredentials(
        ctx: LoginContext,
        predicate: suspend (WalletCredential) -> Boolean
    ): List<WalletCredential> {
        val res = api.credentials(ctx).filter { predicate(it) }
        return res.toList()
    }

    suspend fun findCredentialsById(ctx: LoginContext, vcId: String): WalletCredential? {
        val res = findCredentials(ctx) { it.id == vcId }.firstOrNull()
        return res
    }

    suspend fun findCredentialsByType(ctx: LoginContext, ctype: String): List<WalletCredential> {
        val res = findCredentials(ctx) { wc ->
            val vcJwt = VCDataJwt.fromEncoded(wc.document)
            vcJwt.types.contains(ctype)
        }
        return res
    }

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): WalletCredential? {
        val res = findCredentialsById(ctx, vcId)
        api.deleteCredential(ctx, vcId)
        return res
    }

    // CredentialOffer -------------------------------------------------------------------------------------------------

    fun addCredentialOffer(ctx: LoginContext, credOffer: CredentialOffer): String {
        log.info { "Adding CredentialOffer: ${credOffer.toJson()}" }
        val offerId = withConnection {
            val offerData = CredentialOfferData.fromCredentialOffer(ctx.walletId, credOffer)
            insertCredentialOffer(offerData)
        }
        return offerId
    }

    fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOffer> {
        val res = withConnection {
            selectCredentialOffers(ctx.walletId).associate { co ->
                "${co.offerId}" to co.toCredentialOffer()
            }.toMap()
        }
        return res
    }

    fun getCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        val res = withConnection {
            selectCredentialOffer(ctx.walletId, offerId)?.toCredentialOffer()
        }
        return res
    }

    fun deleteCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        val res = withConnection {
            val wasOffer = selectCredentialOffer(ctx.walletId, offerId)?.toCredentialOffer()
            val delCount = deleteCredentialOffer(ctx.walletId, offerId)
            if (delCount == 1) wasOffer else null
        }
        return res
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun exportKey(ctx: LoginContext, kid: String): String {
        return api.export(ctx, kid)
    }

    suspend fun findKey(ctx: LoginContext, predicate: suspend (Key) -> Boolean): Key? {
        return listKeys(ctx).firstOrNull { predicate(it) }
    }

    suspend fun findKeyByAlgorithm(ctx: LoginContext, algorithm: String): Key? {
        return findKey(ctx) { k -> k.algorithm.equals(algorithm, ignoreCase = true) }
    }

    suspend fun findKeyById(ctx: LoginContext, keyId: String): Key? {
        return findKey(ctx) { k -> k.id == keyId }
    }

    suspend fun findKeyByType(ctx: LoginContext, keyType: KeyType): Key? {
        return findKeyByAlgorithm(ctx, keyType.algorithm)
    }

    suspend fun listKeys(ctx: LoginContext): List<Key> {
        val res: Array<KeyResponse> = api.keys(ctx)
        return res.map { kr -> Key(kr.keyId.id, kr.algorithm) }
    }

    suspend fun createKey(ctx: LoginContext, keyType: KeyType): Key {
        val kid = api.keysGenerate(ctx, keyType)
        return findKeyById(ctx, kid)!!
    }

    suspend fun signWithDid(ctx: LoginContext, did: String, message: String): String {
        val keyId = findDid(ctx) { d -> d.did == did }?.keyId
            ?: throw IllegalStateException("No such did: $did")
        return signWithKey(ctx, keyId, message)
    }

    suspend fun signWithKey(ctx: LoginContext, alias: String, message: String): String {
        return api.keysSign(ctx, alias, message)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun findDid(ctx: LoginContext, predicate: suspend (DidInfo) -> Boolean): DidInfo? {
        return listDids(ctx).firstOrNull { predicate(it) }
    }

    suspend fun findDidByPrefix(ctx: LoginContext, prefix: String): DidInfo? {
        return findDid(ctx) { d -> d.did.startsWith(prefix) }
    }

    suspend fun getDefaultDid(ctx: LoginContext): DidInfo {
        return findDid(ctx) { d -> d.default }
            ?: throw IllegalStateException("No default did for: $ctx.walletId")
    }

    suspend fun getDidDocument(ctx: LoginContext, did: String): JsonObject {
        val didDoc = api.did(ctx, did)
        return didDoc
    }

    suspend fun listDids(ctx: LoginContext): List<DidInfo> {
        val dids = api.dids(ctx)
        return dids.toList()
    }

    suspend fun createDidKey(ctx: LoginContext, alias: String, keyId: String): DidInfo {
        val req = CreateDidKeyRequest(alias, keyId)
        val did: String = api.didsCreateDidKey(ctx, req)
        val didInfo = api.dids(ctx).first { di -> di.did == did }
        return didInfo
    }

    // Private ---------------------------------------------------------------------------------------------------------

}

object CredentialOfferTable : UUIDTable("credential_offers") {
    val walletId = reference("wallet", Wallets, onDelete = ReferenceOption.CASCADE)
    val document = text("document")
    val addedOn = timestamp("added_on")

    fun insertCredentialOffer(offerData: CredentialOfferData): String {
        val offerId = transaction {
            CredentialOfferTable.insertAndGetId {
                it[CredentialOfferTable.walletId] = offerData.walletId
                it[CredentialOfferTable.document] = offerData.document
                it[CredentialOfferTable.addedOn] = offerData.addedOn.toJavaInstant()
            }
        }.value
        return "$offerId"
    }

    fun selectCredentialOffers(walletId: String): List<CredentialOfferData> {
        val res = transaction {
            selectAll().where {
                CredentialOfferTable.walletId eq UUID.fromString(walletId)
            }.map {
                CredentialOfferData(
                    walletId = it[CredentialOfferTable.walletId].value,
                    offerId = it[CredentialOfferTable.id].value,
                    document = it[document],
                    addedOn = it[addedOn].toKotlinInstant()
                )
            }
        }
        return res
    }

    fun selectCredentialOffer(walletId: String, offerId: String): CredentialOfferData? {
        val res = transaction {
            selectAll().where {
                CredentialOfferTable.walletId eq UUID.fromString(walletId)
                CredentialOfferTable.id eq UUID.fromString(offerId)
            }.map {
                CredentialOfferData(
                    walletId = it[CredentialOfferTable.walletId].value,
                    offerId = it[CredentialOfferTable.id].value,
                    document = it[document],
                    addedOn = it[addedOn].toKotlinInstant()
                )
            }.firstOrNull()
        }
        return res
    }

    fun deleteCredentialOffer(walletId: String, offerId: String): Int {
        return transaction {
            CredentialOfferTable.deleteWhere {
                CredentialOfferTable.walletId eq UUID.fromString(walletId)
                CredentialOfferTable.id eq UUID.fromString(offerId)
            }
        }
    }
}

data class CredentialOfferData(
    val walletId: UUID,
    val offerId: UUID,
    val document: String,
    val addedOn: Instant
) {

    companion object {
        fun fromCredentialOffer(walletId: String, credOffer: CredentialOffer): CredentialOfferData {
            val offerId = "${Uuid.random()}"
            val addedOn = Clock.System.now()
            val jsonBytes = credOffer.toJson().toByteArray()
            val encoded = String(Base64.getUrlEncoder().encode(jsonBytes))
            return CredentialOfferData(
                walletId = UUID.fromString(walletId),
                offerId = UUID.fromString(offerId),
                document = encoded,
                addedOn = addedOn)
        }
    }

    fun toCredentialOffer(): CredentialOffer {
        val decoded = String(Base64.getUrlDecoder().decode(document))
        return CredentialOffer.fromJson(decoded)
    }
}
