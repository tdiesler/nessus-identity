package io.nessus.identity.service

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.waltid.DidInfo
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.let

fun createFlattenedJwsJson(jwtHeader: JWSHeader, jwtClaims: JWTClaimsSet): JsonObject {
    val headerBase64 = Base64URL.encode(jwtHeader.toString())
    val payloadBase64 = Base64URL.encode(jwtClaims.toPayload().toString())
    return buildJsonObject {
        put("protected", JsonPrimitive(headerBase64.toString()))
        put("payload", JsonPrimitive(payloadBase64.toString()))
    }
}

fun verifyJwt(signedJWT: SignedJWT, didInfo: DidInfo): Boolean {

    val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
    val verificationMethods = docJson["verificationMethod"] as JsonArray
    val verificationMethod = verificationMethods.let { it[0] as JsonObject }
    val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

    val publicJwk = ECKey.parse(publicKeyJwk)
    val verifier = ECDSAVerifier(publicJwk)
    return signedJWT.verify(verifier)
}
