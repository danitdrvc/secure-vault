/**
 * Axios klijent ka gateway-u (jedina ulazna tačka). Bazni URL je `${gatewayUrl}/api`,
 * pošto gateway sve rute mapira kao `/api/**` → backend. `withCredentials` je uključen
 * radi HttpOnly kolačića sesije koji stižu u Fazi 4.
 */
import axios from 'axios'
import { gatewayUrl } from '../config'

export const apiClient = axios.create({
  baseURL: `${gatewayUrl}/api`,
  withCredentials: true,
})
