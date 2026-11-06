package org.vaultsend

/*
 * Decisions the activity makes about the session and about what other apps hand
 * it, kept free of Android types so SessionTest runs them on the JVM.
 */

/** How long the app may be in the background before its keys are locked. */
const val BACKGROUND_LOCK_MS = 2 * 60 * 1000L

/**
 * Whether the background lock is due, for an app that went to the background at
 * `since` and is back at `now`, both on the clock that keeps counting while the
 * phone sleeps (SystemClock.elapsedRealtime). 0 for `since` means it never left.
 *
 * The timer the activity posts can't be relied on alone: a Handler counts uptime,
 * which stops in deep sleep, and doesn't run at all while Android has the process
 * frozen, so it can fire hours late, and coming back cancels it before it has.
 */
fun backgroundLockDue(since: Long, now: Long): Boolean = since != 0L && now - since >= BACKGROUND_LOCK_MS

/** The parts of a content:// URI that decide whose it is, decoded. */
data class UriParts(val scheme: String?, val authority: String?, val path: List<String>)

/**
 * Whether `uri` lies at or under `grant`: the same scheme and authority, and
 * `grant`'s path segments as the start of its own. This is how Android matches a
 * URI against a prefix grant (Uri.isPathPrefixMatch), on decoded segments, so a
 * different spelling of the same path can't slip past it. Case is ignored, which
 * can only refuse more.
 */
fun UriParts.isWithin(grant: UriParts): Boolean =
    scheme.equals(grant.scheme, ignoreCase = true) &&
        authority.equals(grant.authority, ignoreCase = true) &&
        path.size >= grant.path.size &&
        grant.path.indices.all { path[it] == grant.path[it] }

/**
 * Whether to refuse a URI another app handed over (share sheet, "open with").
 * VaultSend opens it with its own permissions, not the sender's, so a URI to its
 * own FileProvider (`ownAuthority`) or into a folder it holds a grant for
 * (`grants`, its persisted tree grants) would let any app have VaultSend read a
 * file that app can't: a vault folder's parent, say, or an opened copy.
 */
fun refuseIncoming(uri: UriParts, ownAuthority: String, grants: List<UriParts>): Boolean =
    !uri.scheme.equals("content", ignoreCase = true) ||
        uri.authority.equals(ownAuthority, ignoreCase = true) ||
        grants.any { uri.isWithin(it) }
