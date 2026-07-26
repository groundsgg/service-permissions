package gg.grounds.permissions.auth

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.time.Duration
import java.util.HexFormat
import java.util.concurrent.ConcurrentHashMap
import org.eclipse.microprofile.config.inject.ConfigProperty

@ApplicationScoped
class RuntimeReviewCache
@Inject
constructor(
    @ConfigProperty(name = "permissions.runtime.review-cache.positive-ttl") positiveTtl: Duration,
    @ConfigProperty(name = "permissions.runtime.review-cache.maximum-entries") maximumEntries: Int,
) {
    private val ttlNanos =
        positiveTtl.coerceAtLeast(Duration.ZERO).coerceAtMost(MAXIMUM_POSITIVE_TTL).toNanos()
    private val maximumEntries = maximumEntries.coerceIn(1, MAXIMUM_CACHE_ENTRIES)
    private var ticker: () -> Long = System::nanoTime
    private val tokenReviews = ConcurrentHashMap<String, CacheEntry<RuntimeWorkloadIdentity>>()
    private val accessReviews = ConcurrentHashMap<SubjectAccessKey, CacheEntry<Boolean>>()

    internal constructor(
        positiveTtl: Duration,
        maximumEntries: Int,
        ticker: () -> Long,
    ) : this(positiveTtl, maximumEntries) {
        this.ticker = ticker
    }

    fun authenticatedIdentity(token: String): RuntimeWorkloadIdentity? =
        getUnexpired(tokenReviews, tokenDigest(token))

    fun cacheAuthenticatedIdentity(
        token: String,
        identity: RuntimeWorkloadIdentity,
        tokenLifetime: Duration?,
    ) {
        val entryTtlNanos = boundedTtlNanos(tokenLifetime ?: return)
        if (entryTtlNanos == 0L) return
        putBounded(tokenReviews, tokenDigest(token), identity, entryTtlNanos)
    }

    fun allowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean? =
        getUnexpired(accessReviews, SubjectAccessKey(identity, verb, path))

    fun cacheAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String) {
        putBounded(accessReviews, SubjectAccessKey(identity, verb, path), true, ttlNanos)
    }

    private fun tokenDigest(token: String): String =
        HexFormat.of()
            .formatHex(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(UTF_8)))

    private fun <K, V> getUnexpired(cache: ConcurrentHashMap<K, CacheEntry<V>>, key: K): V? {
        val entry = cache[key] ?: return null
        if (ticker() - entry.expiresAtNanos >= 0L) {
            cache.remove(key, entry)
            return null
        }
        return entry.value
    }

    @Synchronized
    private fun <K, V> putBounded(
        cache: ConcurrentHashMap<K, CacheEntry<V>>,
        key: K,
        value: V,
        entryTtlNanos: Long,
    ) {
        if (entryTtlNanos == 0L) return
        pruneExpired(cache)
        if (cache.size >= maximumEntries && !cache.containsKey(key)) {
            cache.keys.firstOrNull()?.let(cache::remove)
        }
        cache[key] = CacheEntry(value, ticker() + entryTtlNanos)
    }

    private fun <K, V> pruneExpired(cache: ConcurrentHashMap<K, CacheEntry<V>>) {
        val now = ticker()
        cache.entries.removeIf { now - it.value.expiresAtNanos >= 0L }
    }

    private fun boundedTtlNanos(lifetime: Duration): Long {
        if (lifetime.isZero || lifetime.isNegative || ttlNanos == 0L) return 0L
        return lifetime.coerceAtMost(Duration.ofNanos(ttlNanos)).toNanos()
    }

    private data class CacheEntry<V>(val value: V, val expiresAtNanos: Long)

    private data class SubjectAccessKey(
        val identity: RuntimeWorkloadIdentity,
        val verb: String,
        val path: String,
    )

    private companion object {
        val MAXIMUM_POSITIVE_TTL: Duration = Duration.ofSeconds(60)
        const val MAXIMUM_CACHE_ENTRIES = 4096
    }
}
