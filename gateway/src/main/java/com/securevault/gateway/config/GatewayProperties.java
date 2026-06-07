package com.securevault.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Konfiguracija gateway-a vezana na {@code app.*} (vidi application.yml).
 *
 * <p>Pokriva IpGuardFilter pragove (Faza 9) i parametre za prijavu sigurnosnih događaja
 * backendu ({@code /internal/**}, deljeni token).
 */
@ConfigurationProperties(prefix = "app")
public class GatewayProperties {

    /** Bazni URL backenda za interne (server-to-server) pozive. */
    private String backendUri = "http://localhost:8081";

    /** Deljeni token koji backend zahteva u {@code X-Internal-Token} zaglavlju. */
    private String internalToken;

    private final Ipguard ipguard = new Ipguard();

    public String getBackendUri() {
        return backendUri;
    }

    public void setBackendUri(String backendUri) {
        this.backendUri = backendUri;
    }

    public String getInternalToken() {
        return internalToken;
    }

    public void setInternalToken(String internalToken) {
        this.internalToken = internalToken;
    }

    public Ipguard getIpguard() {
        return ipguard;
    }

    /** Pragovi IpGuardFilter-a. */
    public static class Ipguard {

        /** Broj strike-ova (neuspeli login / sumnjiv zahtev) posle kojeg se IP blokira. */
        private int maxStrikes = 5;

        /** Prozor u kome se strike-ovi broje (sekunde). */
        private int strikeWindowSec = 60;

        /** Trajanje privremenog bloka IP-a (sekunde). */
        private int blockTtlSec = 300;

        public int getMaxStrikes() {
            return maxStrikes;
        }

        public void setMaxStrikes(int maxStrikes) {
            this.maxStrikes = maxStrikes;
        }

        public int getStrikeWindowSec() {
            return strikeWindowSec;
        }

        public void setStrikeWindowSec(int strikeWindowSec) {
            this.strikeWindowSec = strikeWindowSec;
        }

        public int getBlockTtlSec() {
            return blockTtlSec;
        }

        public void setBlockTtlSec(int blockTtlSec) {
            this.blockTtlSec = blockTtlSec;
        }
    }
}
