// OID4VP response encryption (encryption only, per VP 1.0): ECDH-ES + A128GCM.
import { CompactEncrypt, compactDecrypt, importPKCS8, importJWK, calculateJwkThumbprint } from 'jose';

const te = new TextEncoder();
const td = new TextDecoder();

/** Wallet side: encrypt the response object to the verifier's enc public JWK. */
export async function encryptResponse(payloadObj, recipientPublicJwk) {
  const pub = await importJWK(recipientPublicJwk, 'ECDH-ES');
  return new CompactEncrypt(te.encode(JSON.stringify(payloadObj)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
    .encrypt(pub);
}

/** Verifier side: decrypt with the enc private key (PKCS8 PEM). */
export async function decryptResponse(jwe, recipientPrivatePem) {
  const priv = await importPKCS8(recipientPrivatePem.toString(), 'ECDH-ES');
  const { plaintext } = await compactDecrypt(jwe, priv);
  return JSON.parse(td.decode(plaintext));
}

export { calculateJwkThumbprint };
