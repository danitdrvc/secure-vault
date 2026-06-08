/**
 * Bazni URL gateway-a (jedina ulazna tačka). U dev/docker okruženju dolazi iz
 * VITE_GATEWAY_URL; fallback je lokalni gateway port.
 */
export const gatewayUrl: string =
  import.meta.env.VITE_GATEWAY_URL ?? 'https://localhost:8080'
