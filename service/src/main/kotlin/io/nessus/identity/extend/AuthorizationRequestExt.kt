package io.nessus.identity.extend

import id.walt.oid4vc.requests.AuthorizationRequest
import kotlinx.serialization.json.Json
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

fun AuthorizationRequest.getQueryParameters(): String {
    val sb = StringBuilder()
    sb.append("response_type=${responseType.first().value}")
    sb.append("&client_id=${clientId}")
    sb.append("&redirect_uri=${redirectUri}")
    scope.let {
        val txt = it.joinToString(" ")
        sb.append("&scope=${urlEncode(txt)}")
    }
    authorizationDetails?.let {
        val json = Json.encodeToString(it)
        sb.append("&authorization_details=${urlEncode(json)}")
    }
    codeChallenge?.let {
        sb.append("&code_challenge=${urlEncode(it)}")
    }
    codeChallengeMethod?.let {
        sb.append("&code_challenge_method=${urlEncode(it)}")
    }
    return sb.toString()
}

// Private -----------------------------------------------------------------------------------------------------------------------------------------------------

private fun urlEncode(json: String): String =
    URLEncoder.encode(json, StandardCharsets.UTF_8)
