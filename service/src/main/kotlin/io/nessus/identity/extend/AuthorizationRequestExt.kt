package io.nessus.identity.extend

import io.nessus.identity.service.urlEncode
import io.nessus.identity.types.AuthorizationRequestDraft11
import kotlinx.serialization.json.*

fun AuthorizationRequestDraft11.getQueryParameters(): String {
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
