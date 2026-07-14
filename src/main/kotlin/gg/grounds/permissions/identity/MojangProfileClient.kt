package gg.grounds.permissions.identity

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.LinkedHashMap
import java.util.Locale
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty

data class MojangProfile(val playerId: UUID, val name: String)

sealed interface MojangLookupResult {
    data class Found(val profile: MojangProfile) : MojangLookupResult

    data object NotFound : MojangLookupResult

    data object Unavailable : MojangLookupResult
}

@ApplicationScoped
class MojangProfileClient(
    private val objectMapper: ObjectMapper,
    private val baseUrl: String,
    private val timeout: Duration,
    private val httpClient: HttpClient,
    private val clock: Clock = Clock.systemUTC(),
    private val cacheTtl: Duration = DEFAULT_CACHE_TTL,
    private val cacheMaxEntries: Int = DEFAULT_CACHE_MAX_ENTRIES,
) {
    private val cache =
        object : LinkedHashMap<String, CachedLookup>(16, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<String, CachedLookup>?
            ): Boolean = size > cacheMaxEntries
        }

    @Inject
    constructor(
        objectMapper: ObjectMapper,
        @ConfigProperty(name = "permissions.mojang.base-url") baseUrl: String,
        @ConfigProperty(name = "permissions.mojang.timeout") timeout: Duration,
        @ConfigProperty(name = "permissions.mojang.cache-ttl") cacheTtl: Duration,
        @ConfigProperty(name = "permissions.mojang.cache-max-entries") cacheMaxEntries: Int,
    ) : this(
        objectMapper = objectMapper,
        baseUrl = baseUrl,
        timeout = timeout,
        httpClient = HttpClient.newBuilder().connectTimeout(timeout).build(),
        cacheTtl = cacheTtl,
        cacheMaxEntries = cacheMaxEntries,
    )

    init {
        require(!cacheTtl.isZero && !cacheTtl.isNegative) { "Mojang cache TTL must be positive" }
        require(cacheMaxEntries > 0) { "Mojang cache size must be positive" }
    }

    fun lookupExactUsername(username: String): MojangLookupResult {
        if (!isValidMinecraftUsername(username)) {
            return MojangLookupResult.NotFound
        }
        val cacheKey = username.lowercase(Locale.ROOT)
        cached(cacheKey)?.let {
            return it
        }
        val result = requestProfile(username)
        cache(cacheKey, result)
        return result
    }

    private fun requestProfile(username: String): MojangLookupResult {
        val request =
            HttpRequest.newBuilder(profileUri(username))
                .timeout(timeout)
                .header("Accept", "application/json")
                .GET()
                .build()
        return try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            when (response.statusCode()) {
                200 -> parseProfile(username, response.body())
                204,
                404 -> MojangLookupResult.NotFound
                else -> MojangLookupResult.Unavailable
            }
        } catch (_: Exception) {
            MojangLookupResult.Unavailable
        }
    }

    private fun cached(cacheKey: String): MojangLookupResult? =
        synchronized(cache) {
            val cached = cache[cacheKey] ?: return@synchronized null
            if (clock.instant().isBefore(cached.expiresAt)) {
                cached.result
            } else {
                cache.remove(cacheKey)
                null
            }
        }

    private fun cache(cacheKey: String, result: MojangLookupResult) {
        synchronized(cache) {
            cache[cacheKey] = CachedLookup(result, clock.instant().plus(cacheTtl))
        }
    }

    private fun parseProfile(requestedUsername: String, body: String): MojangLookupResult =
        try {
            val payload = objectMapper.readValue(body, MojangProfilePayload::class.java)
            require(isValidMinecraftUsername(payload.name)) {
                "Mojang profile name must be a valid Minecraft username"
            }
            require(payload.name.equals(requestedUsername, ignoreCase = true)) {
                "Mojang profile name must match the requested username"
            }
            MojangLookupResult.Found(
                MojangProfile(playerId = hyphenatedUuid(payload.id), name = payload.name)
            )
        } catch (_: Exception) {
            MojangLookupResult.Unavailable
        }

    private fun profileUri(username: String): URI {
        val encoded = URLEncoder.encode(username, StandardCharsets.UTF_8)
        return URI.create("${baseUrl.trimEnd('/')}/users/profiles/minecraft/$encoded")
    }

    private fun hyphenatedUuid(value: String): UUID {
        val compact = value.replace("-", "")
        require(compact.length == 32) {
            "Mojang profile UUID must contain 32 hexadecimal characters"
        }
        return UUID.fromString(
            "${compact.substring(0, 8)}-${compact.substring(8, 12)}-${compact.substring(12, 16)}-" +
                "${compact.substring(16, 20)}-${compact.substring(20)}"
        )
    }

    private data class MojangProfilePayload(var id: String = "", var name: String = "")

    private data class CachedLookup(val result: MojangLookupResult, val expiresAt: Instant)

    private companion object {
        val DEFAULT_CACHE_TTL: Duration = Duration.ofMinutes(5)
        const val DEFAULT_CACHE_MAX_ENTRIES = 512
    }
}
