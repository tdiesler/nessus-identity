package io.nessus.identity.service


import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import id.walt.oid4vc.data.dif.PresentationDefinition
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test

class WalletServiceTest : AbstractServiceTest() {

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun registerUser() {
        runBlocking {

            // Check whether Max already exists
            //
            var ctx: LoginContext? = null
            try {
                ctx = walletService.login(Max.toLoginParams())
            } catch (ex: Exception) {
                if (ex.message?.contains("Unknown user") == false) {
                    throw ex
                }
            }

            if (ctx == null) {
                val success = walletService.registerUser(Max.toRegisterUserParams())
                success shouldBe "Registration succeeded"
            }
        }
    }

    @Test
    fun userLogin() {
        runBlocking {
            val ctx = walletService.login(Max.toLoginParams())
            ctx.authToken.shouldNotBeBlank()
            ctx.maybeWalletInfo.shouldBeNull()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun listWallets() {
        runBlocking {
            authLogin(Max)
            val wallets = walletService.listWallets()
            wallets.shouldNotBeEmpty()
        }
    }

    // Credentials -----------------------------------------------------------------------------------------------------

    @Test
    fun listCredentials() {
        runBlocking {
            authLoginWithWallet(Max)
            val credentials = walletService.listCredentials()
            credentials.shouldNotBeNull()
        }
    }

    @Test
    fun findCredentials() {

        val json = loadResourceAsString("presentation-definition.json")
        val vpdef = Json.decodeFromString<PresentationDefinition>(json)
        log.info { "PresentationDefinition: $vpdef" }

        runBlocking {
            authLoginWithWallet(Max)
            walletService.findCredentials(vpdef).forEach { (_, wc) ->
                print("${wc.parsedDocument?.get("type")}\n")
            }
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun listKeys() {
        runBlocking {
            authLoginWithWallet(Max)
            val keys = walletService.listKeys()
            keys.shouldNotBeEmpty()
        }
    }

    @Test
    fun createKey() {
        runBlocking {
            authLoginWithWallet(Max)
            val key = walletService.createKey(KeyType.SECP256R1)
            key.algorithm shouldBe KeyType.SECP256R1.algorithm
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun listDids() {
        runBlocking {
            authLoginWithWallet(Max)
            val res = walletService.listDids()
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun createDidKey() {
        runBlocking {
            authLoginWithWallet(Max)
            val keys = walletService.listKeys()
            val alias = "did:key#${keys.size + 1}"
            walletService.findDidByPrefix("did:key")?: runBlocking {
                val key = walletService.findKeyByType(KeyType.SECP256R1)
                val didInfo = walletService.createDidKey(alias, key?.id ?: "")
                didInfo.did.shouldNotBeBlank()
            }
        }
    }

    @Test
    fun signVerifyWithDid() {
        runBlocking {
            authLoginWithWallet(Max)
            val didInfo = walletService.findDidByPrefix("did:key").shouldNotBeNull()
            val signJwt = walletService.signWithDid(didInfo.did, "Kermit")
            signJwt.shouldNotBeBlank()

            val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
            val verificationMethods = docJson["verificationMethod"] as JsonArray
            val verificationMethod = verificationMethods.let { it[0] as JsonObject }
            val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

            val publicJwk = ECKey.parse(publicKeyJwk)
            val verifier = ECDSAVerifier(publicJwk)

            // JWT-style split
            val parts = signJwt.split('.')
            parts.size shouldBe 3

            val header = JWSHeader.parse(Base64URL.from(parts[0]))
            val signature = Base64URL.from(parts[2])

            val signedContent = "${parts[0]}.${parts[1]}"
            val success = verifier.verify(header, signedContent.toByteArray(), signature)
            success shouldBe true
        }
    }

    // Logout ----------------------------------------------------------------------------------------------------------

    @Test
    fun userLogout() {
        runBlocking {
            walletService.logout()
        }
    }
}