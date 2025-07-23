package io.nessus.identity.service

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.waltid.DidInfo
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

@Serializable
data class FlattenedJws(
    val protected: String,
    val payload: String,
)

fun SignedJWT.createFlattenedJws(): FlattenedJws {
    val headerBase64 = this.header.toBase64URL()
    val payloadBase64 = this.jwtClaimsSet.toPayload().toBase64URL()
    return FlattenedJws("$headerBase64", "$payloadBase64")
}

suspend fun SignedJWT.signWithKey(ctx: LoginContext, kid: String): SignedJWT {
    val signingInput = Json.encodeToString(this.createFlattenedJws())
    val signedEncoded = widWalletSvc.signWithKey(ctx, kid, signingInput)
    return SignedJWT.parse(signedEncoded)
}

fun SignedJWT.verifyJwt(didInfo: DidInfo): Boolean {

    val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
    val verificationMethods = docJson["verificationMethod"] as JsonArray
    val verificationMethod = verificationMethods.let { it[0] as JsonObject }
    val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

    val publicJwk = ECKey.parse(publicKeyJwk)
    val verifier = ECDSAVerifier(publicJwk)
    return this.verify(verifier)
}
