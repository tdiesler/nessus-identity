package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider
import kotlinx.serialization.Serializable
import java.util.jar.Manifest

fun loadManifestFromClasspath(): Manifest {
    val classLoader = Thread.currentThread().contextClassLoader
    val manifestStream = classLoader.getResourceAsStream("META-INF/MANIFEST.MF")
        ?: throw IllegalStateException("No META-INF/MANIFEST.MF")
    return manifestStream.use { Manifest(it) }
}

@Serializable
data class VersionInfo(
    val version: String,
    val revision: String? = null,
    )

fun getVersionInfo(): VersionInfo {
    val manifest = loadManifestFromClasspath()
    val attributes = manifest.mainAttributes
    val buildVersion = attributes.getValue("Build-Version")  ?: ConfigProvider.root.version
    val buildRevision = attributes.getValue("Build-Revision")?.substring(0, 7)
    return VersionInfo(buildVersion, buildRevision)
}
