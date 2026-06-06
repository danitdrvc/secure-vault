package com.securevault.user.domain;

/** Stanje naloga; mapira se na users.status varchar (@Enumerated STRING). */
public enum UserStatus {
    ACTIVE,
    FROZEN,
    DEACTIVATED
}
