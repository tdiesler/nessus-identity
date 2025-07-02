package io.nessus.identity.service

// Authentication ------------------------------------------------------------------------------------------------------

enum class LoginType(val type: String) { EMAIL("email") }

data class LoginParams(val type: LoginType, val email: String, val password: String) {
    fun toAuthLoginRequest() : LoginRequest {
        return LoginRequest(type.type, email, password)
    }
}

data class RegisterUserParams(val type: LoginType, val name: String, val email: String, val password: String) {
    fun toAuthRegisterRequest() : RegisterUserRequest {
        return RegisterUserRequest(type.type, name, email, password)
    }
}

// Keys ----------------------------------------------------------------------------------------------------------------

enum class KeyType(val algorithm: String) {
    ED25519("Ed25519"),
    SECP256R1("secp256r1");

    override fun toString(): String = algorithm
}

data class Key(val id: String, val algorithm: String)

// Users ----------------------------------------------------------------------------------------------------------------

open class User(val name: String, val email: String, val password: String) {
    fun toLoginParams() : LoginParams {
        return LoginParams(LoginType.EMAIL, email, password)
    }
    fun toRegisterUserParams() : RegisterUserParams {
        return RegisterUserParams(LoginType.EMAIL, name, email, password)
    }
}

object Alice : User("Alice", "alice@email.com", "password")
object Max : User("Max Mustermann", "user@email.com", "password")
