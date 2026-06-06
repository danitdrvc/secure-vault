/**
 * Bajt-niz garantovano podržan običnim `ArrayBuffer`-om (ne `SharedArrayBuffer`).
 *
 * Web Crypto (`BufferSource`) prihvata samo poglede nad `ArrayBuffer`-om, pa sve
 * binarne ulaze/izlaze kripto sloja tipiziramo ovim aliasom umesto golog
 * `Uint8Array` (čiji je podrazumevani parametar `ArrayBufferLike`).
 */
export type Bytes = Uint8Array<ArrayBuffer>
