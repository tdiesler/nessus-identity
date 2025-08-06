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
