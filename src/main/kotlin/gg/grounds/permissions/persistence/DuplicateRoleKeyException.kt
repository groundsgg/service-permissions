package gg.grounds.permissions.persistence

class DuplicateRoleKeyException(val roleKey: String, cause: Throwable) :
    RuntimeException("Duplicate role key (roleKey=$roleKey)", cause)
