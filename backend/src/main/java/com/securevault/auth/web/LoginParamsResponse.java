package com.securevault.auth.web;

/** KDF parametri za reprodukciju master ključa na klijentu (salt je base64). */
public record LoginParamsResponse(String kdfSalt, int kdfIterations) {
}
