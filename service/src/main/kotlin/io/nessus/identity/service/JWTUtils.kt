package io.nessus.identity.service

import kotlinx.serialization.Serializable

@Serializable
data class FlattenedJws(
    val protected: String,
    val payload: String,
)
