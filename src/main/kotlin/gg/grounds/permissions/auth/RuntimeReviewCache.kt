package gg.grounds.permissions.auth

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
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
    private var clock: Clock = Clock.systemUTC()
    private val tokenReviews = ConcurrentHashMap<String, CacheEntry<RuntimeWorkloadIdentity>>()
    private val accessReviews = ConcurrentHashMap<SubjectAccessKey, CacheEntry<Boolean>>()

    internal constructor(
        positiveTtl: Duration,
        maximumEntries: Int,
        ticker: () -> Long,
        clock: Clock = Clock.systemUTC(),
    ) : this(positiveTtl, maximumEntries) {
        this.ticker = ticker
        this.clock = clock
    }

    fun authenticatedIdentity(token: String): RuntimeWorkloadIdentity? =
        getUnexpired(tokenReviews, tokenDigest(token))

    fun cacheAuthenticatedIdentity(
        token: String,
        identity: RuntimeWorkloadIdentity,
        tokenExpiresAt: Instant?,
    ) {
        val absoluteExpiresAt = tokenExpiresAt?.takeIf { it.isAfter(clock.instant()) } ?: return
        putBounded(tokenReviews, tokenDigest(token), identity, ttlNanos, absoluteExpiresAt)
    }

    fun allowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean? =
        getUnexpired(accessReviews, SubjectAccessKey(identity, verb, path))

    fun cacheAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String) {
        putBounded(
            accessReviews,
            SubjectAccessKey(identity, verb, path),
            true,
            ttlNanos,
            absoluteExpiresAt = null,
        )
    }

    private fun tokenDigest(token: String): String =
        HexFormat.of()
            .formatHex(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(UTF_8)))

    private fun <K, V> getUnexpired(cache: ConcurrentHashMap<K, CacheEntry<V>>, key: K): V? {
        val entry = cache[key] ?: return null
        if (isExpired(entry, ticker(), clock.instant())) {
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
        absoluteExpiresAt: Instant?,
    ) {
        if (entryTtlNanos == 0L) return
        pruneExpired(cache)
        if (cache.size >= maximumEntries && !cache.containsKey(key)) {
            cache.keys.firstOrNull()?.let(cache::remove)
        }
        cache[key] = CacheEntry(value, ticker() + entryTtlNanos, absoluteExpiresAt)
    }

    private fun <K, V> pruneExpired(cache: ConcurrentHashMap<K, CacheEntry<V>>) {
        val nowNanos = ticker()
        val now = clock.instant()
        cache.entries.removeIf { isExpired(it.value, nowNanos, now) }
    }

    private fun isExpired(entry: CacheEntry<*>, nowNanos: Long, now: Instant): Boolean =
        nowNanos - entry.expiresAtNanos >= 0L ||
            entry.absoluteExpiresAt?.let { !now.isBefore(it) } == true

    private data class CacheEntry<V>(
        val value: V,
        val expiresAtNanos: Long,
        val absoluteExpiresAt: Instant?,
    )

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
