package gg.grounds.permissions.persistence

class CatalogSourceConflictException(
    val permissionKey: String,
    val existingSource: String,
    val requestedSource: String,
) :
    RuntimeException(
        "Catalog source conflict (permissionKey=$permissionKey, existingSource=$existingSource, requestedSource=$requestedSource)"
    )
