// Verifier (Relying Party): builds HAIP-shaped OID4VP requests (DCQL + response
// encryption) and verifies the encrypted vp_token. Supports single requests and
// session-linked sequential requests (PID -> EAA) checking same-holder binding.
import { fileURLToPath } from 'node:url';
import { randomBytes, X509Certificate, createPrivateKey, createPublicKey, generateKeyPairSync, createHash } from 'node:crypto';
import { verifyDeviceResponse } from './mdoc.mjs';
import { verifySdJwtPresentation } from './sdjwt.mjs';
import { readFeatures } from './features.mjs';
import { annexDSessionTranscript, annexCSessionTranscript, oid4vpRedirectSessionTranscript, buildEncryptionInfo, hpkeSuite, annexCOpen, decodeAnnexCResponse, dcApiAud, cborEncode, b64url, coseKeyFromJwk } from './handover.mjs';
import { fromB64url } from './cbor.mjs';
import { SignJWT, importPKCS8 } from 'jose';
import { decryptResponse, calculateJwkThumbprint } from './jwe.mjs';
import { buildDcql, satisfies, missingPresentations } from './dcql.mjs';
import { buildDeviceRequest } from './device-request.mjs';
import { rawVpRepr } from './vpdebug.mjs';
import { verifyStatus } from './status.mjs';
import { memoryStore } from './oid4vci.mjs';

// **nonce は 32 バイト**（2026-08-26・conformance suite が検出）。16 バイトでも
// 乱数としては 128 ビットあるが、suite は **文字列の Shannon エントロピー**を測って
// 96 ビットを要求する（OID4VP 1.0 §5.2「fresh, cryptographically random number with
// sufficient entropy」・OpenID4VP PR #722）。base64url 22 文字では推定 90 ビットにしか
// ならず届かない——**「乱数の強度」と「測られ方」は別**なので、測られ方に余裕を持たせる。
const rand = () => randomBytes(32).toString('base64url');
// 取引 ID は URL とストアのキーで、エントロピーの検査対象ではないので 16 バイトのまま
const randId = () => randomBytes(16).toString('base64url');

/**
 * **応答暗号化の鍵は要求ごとに作る**（2026-08-26・conformance suite が検出）。
 * OID4VP 1.0 §5.1 は client_metadata の `jwks` を「This allows the Verifier to pass
 * ephemeral keys specific to this Authorization Request」と定め、§8.3 / HAIP §5.5 は
 * 要求ごとの一時鍵を MUST とする。使い回すと (1) 過去の応答を1つの鍵で遡って復号でき、
 * (2) **同じ公開鍵が RP 間・要求間の相関子**になる（我々が unlinkability を掲げている面）。
 * 秘密鍵は `vp:<txn>` に置き、復号時にそこから読む（取引が消えれば鍵も消える）。
 */
const newEphemeralEncKey = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    encPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    encJwk: publicKey.export({ format: 'jwk' }),
  };
};
const holderId = (jwk) => `${jwk.x}.${jwk.y}`; // normalize holder key across formats

/** 自己署名＝トラストアンカー。x5c から落とすため（sdjwt.mjs と同じ規則）。 */
function isSelfSignedDer(der) {
  try {
    const c = new X509Certificate(Buffer.from(der));
    return c.subject === c.issuer && c.verify(c.publicKey);
  } catch { return false; }
}

export class VerifierService {
  // encPrivatePem / trustedIacaDer / trustedIssuerCaDer: explicit in Workers (from env);
  // null triggers lazy disk load in Node.js dev via _ensurePki().
  constructor({ store = memoryStore(),
    clientId = 'x509_san_dns:verifier.ihv.example',
    origin = 'https://verifier.ihv.example',
    clientName = 'IHV デモ検証者（RP）',
    encPrivatePem = null, trustedIacaDer = null, trustedIssuerCaDer = null,
    readerKeyPem = null, readerCertDer = null, readerCaDer = null,
    rpKeyPem = null, rpCertDer = null, rpCaDer = null,
    statusResolver = null, trustResolver = null } = {}) {
    this.store = store; this.clientId = clientId; this.origin = origin;
    this.clientName = clientName;
    this.readerKeyPem = readerKeyPem; this.readerCertDer = readerCertDer; this.readerCaDer = readerCaDer;
    // JAR 署名／x509_san_dns の RP 証明書（reader とは用途が違う。_ensurePki 参照）
    this.rpKeyPem = rpKeyPem; this.rpCertDer = rpCertDer; this.rpCaDer = rpCaDer;
    this.statusResolver = statusResolver;
    // トラストリスト由来のアンカー（issue #26/#28）。**有れば正本**——バンドルに焼いた
    // `trustedIacaDer` / `trustedIssuerCaDer` は、リストが引けない環境（テスト・オフライン）
    // のための土台として残す。差し替えたいときにリストだけ直せるのがこの層の目的
    this.trustResolver = trustResolver;
    this._trustedIacaDer = trustedIacaDer;
    this._trustedIssuerCaDer = trustedIssuerCaDer;
    if (encPrivatePem) this._initKeys(encPrivatePem, trustedIacaDer, trustedIssuerCaDer);
  }

  _initKeys(encPrivatePem, iacaDer, caDer) {
    this.encPrivatePem = encPrivatePem;
    this.encJwk = createPublicKey(encPrivatePem).export({ format: 'jwk' });
    this.encPrivJwk = createPrivateKey(encPrivatePem).export({ format: 'jwk' });
    this.trustedIacaDer = iacaDer;
    this.trustedIssuerCaDer = caDer;
  }

  /** RP response-encryption public key set (ECDH-ES). Served at the hosted /jwks and
   *  embedded inline in client_metadata. */
  jwksSet() { return { keys: [{ ...this.encJwk, use: 'enc', alg: 'ECDH-ES', kid: 'rp-enc-1' }] }; }

  /** RP client_metadata (OpenID4VP). Embedded inline in requests today; also served at
   *  the hosted /client-metadata so a `client_metadata_uri` reference is possible. */
  /**
   * 認可要求を **署名済み要求オブジェクト（JAR・RFC 9101）** にする。
   *
   * なぜ要るか（2026-08-26・conformance suite が検出）: OID4VP 1.0 の Request URI は
   * **`application/oauth-authz-req+jwt` で署名済み JWT を返す**のが規定で、我々は素の
   * JSON を返していた。しかも unsigned のまま `client_id` を載せており
   * （「MUST be omitted in unsigned requests」）、二重に非準拠だった。署名すれば
   * `client_id` は正当な RP 識別子になり、両方が同時に解ける。
   *
   * 署名鍵は **readerAuth と同じ RP 証明書**（pki/verifier/rp.*）を使う。x5c を載せるので
   * ウォレットは証明書チェーンで RP を認証できる。**鍵が無ければ null を返し、
   * 呼び出し側は素の JSON にフォールバックする**——Workers に鍵を配れていない環境で
   * 提示が丸ごと止まるより、署名なしでも動くほうがデモとして安全（鍵の有無は
   * `/dev/endpoints` で見える）。
   */
  async signRequestObject(request) {
    // **署名は RP 証明書で行う**（2026-08-26）。以前は readerAuth の鍵を流用していたが、
    // あれは ISO 18013-5 の mdoc reader 専用 EKU(1.0.18013.5.1.6) を持つ証明書で用途が違い、
    // しかも SAN が無いので `x509_san_dns` の client_id と照合できなかった。
    // **無ければ null を返し、呼び出し側は unsigned（redirect_uri prefix）に落ちる。**
    if (!this.rpKeyPem || !this.rpCertDer) return null;
    // **トラストアンカー（自己署名ルート）を x5c に入れない**（2026-08-26・conformance
    // suite が検出）。SD-JWT VC でまったく同じ規則を守っていたのに JAR で踏み直した——
    // 理由も同じで、**届いたチェーンだけで検証が完結してしまう**から。ウォレットは
    // 自分の持つアンカーへ辿れなければ拒否しなければならない。
    // 中間 CA を挟んでも自動で正しく載るよう、リーフ以外の自己署名だけを落とす。
    const x5c = [this.rpCertDer, ...(this.rpCaDer ? [this.rpCaDer] : [])]
      .filter((d, i) => i === 0 || !isSelfSignedDer(d))
      .map((d) => Buffer.from(d).toString('base64'));
    const key = await importPKCS8(
      typeof this.rpKeyPem === 'string' ? this.rpKeyPem : this.rpKeyPem.toString('utf8'), 'ES256');
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...request, iss: request.client_id, aud: 'https://self-issued.me/v2' })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c })
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(key);
  }

  /**
   * **client_metadata は閉じた集合**（2026-08-26・conformance suite が検出）。
   * OID4VP 1.0 §5.1「Other metadata parameters MUST be ignored unless a profile of this
   * specification explicitly defines them as usable in the `client_metadata` parameter.」
   * 定義されているのは **jwks / encrypted_response_enc_values_supported /
   * vp_formats_supported** の3つだけ。我々は次の3つを載せていて全部 unknown だった:
   * - `authorization_encrypted_response_alg` / `_enc` … 1.0 Final で廃止。
   *   内容暗号は `encrypted_response_enc_values_supported`（配列）が引き継ぎ、
   *   鍵合意アルゴリズムは jwks の鍵自身（`alg`）が語る
   * - `client_name` … OIDC Dynamic Client Registration の項目でここには無い。
   *   **「MUST be ignored」＝載せても機能しない**ので、RP 名はデモ拡張として
   *   要求のトップレベル（`rp_name`）へ移した。purpose と同じ扱い。
   *   仕様上の正攻法は verifier_info（RP 属性証明）だが HAIP 相当で重い
   * @param {object} encJwk この要求専用の一時公開鍵
   */
  clientMetadata(encJwk = this.encJwk) {
    return {
      jwks: { keys: [{ ...encJwk, use: 'enc', alg: 'ECDH-ES', kid: 'rp-enc-1' }] },
      // **HAIP §5 は A128GCM と A256GCM の両方を要求する**（2026-08-27・suite が検出）:
      // 「Verifiers MUST list both `A128GCM` and `A256GCM` in
      //  `encrypted_response_enc_values_supported` in their client metadata.」
      // ウォレット側は「どちらか一方または両方」でよい（非対称な要求）。
      // **広告できるのは実際に復号できるから**——`decryptResponse` は `enc` を固定せず
      // JWE ヘッダの値で復号するので、どちらで暗号化されても受けられる
      encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
      vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] }, mso_mdoc: { alg: ['ES256'] } },
    };
  }

  /**
   * この応答を検証するときのトラストアンカー。トラストリストが引ければ**その束**、
   * 引けなければバンドルの1枚。**リストが引けたのに0件なら fail-closed**（空配列を返し、
   * 検証側が「アンカーが無い」で落ちる）——引けないときに素通しさせないため。
   */
  async _anchors() {
    const base = {
      issuer: this.trustedIacaDer ? [this.trustedIacaDer] : [],
      sdjwt: this.trustedIssuerCaDer ? [this.trustedIssuerCaDer] : [],
    };
    // `all` = 発行者側アンカーの総和。**Status List の署名者はこれで見る**——
    // mdoc のリストは IACA 配下、SD-JWT のリストは SD-JWT CA 配下（独立2ルート・#25）で、
    // どちらに繋がるかは配布 URI からしか分からない。束で見れば取り違えようがない
    const withAll = (o) => ({ ...o, all: [...new Set([...o.issuer, ...o.sdjwt])] });
    if (!this.trustResolver) return withAll({ ...base, fromList: false });
    try {
      const r = await this.trustResolver.resolve();
      const ders = r.issuerCas.map((a) => a.der);
      if (!ders.length) return { issuer: [], sdjwt: [], all: [], fromList: true, errors: r.errors };
      // 形式のラベルは付けない——mdoc の資格証が SD-JWT CA へ繋がることはあり得ないので、
      // 発行者アンカーの束を丸ごと試せば結果は同じ（リストの記述ミスに強い）
      return withAll({ issuer: ders, sdjwt: ders, fromList: true, errors: r.errors });
    } catch { return withAll({ ...base, fromList: false }); }
  }

  async _ensurePki() {
    if (this.encPrivatePem) return;
    // Node.js fallback — never reached in Workers (PKI injected via constructor)
    const { readFileSync } = await import('node:fs');
    const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
    const der = (rel) => new X509Certificate(readFileSync(root(rel))).raw;
    this._initKeys(
      readFileSync(root('pki/verifier/rp-enc.key')),
      this._trustedIacaDer ?? der('pki/mdoc/iaca/iaca.crt'),
      this._trustedIssuerCaDer ?? der('pki/sdjwt/issuer-ca.crt'),
    );
    // Reader Authentication 用鍵（Annex C readerAuth）。無ければ署名なしで組む（optional）
    try {
      this.readerKeyPem ??= readFileSync(root('pki/reader/reader.key'));
      this.readerCertDer ??= der('pki/reader/reader.crt');
      this.readerCaDer ??= der('pki/reader/reader-ca.crt');
    } catch { /* reader PKI 未生成環境では readerAuth を省略 */ }
    // JAR 署名＋x509_san_dns 用（**reader とは別系統**・SAN 付き）。同じく optional
    try {
      this.rpKeyPem ??= readFileSync(root('pki/verifier/rp.key'));
      this.rpCertDer ??= der('pki/verifier/rp.crt');
      this.rpCaDer ??= der('pki/verifier/rp-ca.crt');
    } catch { /* 無ければ signed 要求は作れない＝redirect_uri prefix に落ちる */ }
  }

  /** Build a presentation request. protocol: 'annex-d' (OID4VP/HAIP over DC API,
   *  JWE) or 'annex-c' (org-iso-mdoc, HPKE). Annex C is mdoc-only.
   *
   * `clientIdPrefix` は **署名の有無と一体**（OID4VP 1.0 §5.9.3・2026-08-26）。
   * 独立した2つのつまみではない:
   * - `redirect_uri` … 「Requests using the `redirect_uri` Client Identifier Prefix
   *   **cannot be signed** because there is no method for the Wallet to obtain a
   *   trusted key for verification.」＝ RP 認証なし。client_id は response_uri と一致
   * - `x509_san_dns` … 「The request **MUST be signed** with the private key
   *   corresponding to the public key in the leaf X.509 certificate」。client_id の
   *   prefix 以降が証明書の dNSName SAN と一致する必要がある＝ RP を認証できる
   * - `x509_hash`（2026-08-29・HAIP 1.0 §5 が MUST。conformance suite の
   *   `oid4vp-1final-verifier-haip-test-plan` は全モジュールがこの prefix 固定）。
   *   §5.9.3 原文:「the original Client Identifier (the part without the `x509_hash:`
   *   prefix) MUST be a hash and match the hash of the leaf certificate passed with
   *   the request. The request MUST be signed with the private key corresponding to
   *   the public key in the leaf X.509 certificate of the certificate chain added to
   *   the request in the `x5c` JOSE header parameter … The value of `x509_hash` is
   *   the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509
   *   certificate.」＝ `x509_san_dns` と同じ RP 証明書・同じ署名要件で、
   *   **client_id の作り方だけが「SAN のホスト名」から「証明書DERのSHA-256」に変わる**。
   *   x509_san_dns の定義文にある「FQDN of the redirect_uri value MUST match」という
   *   条項は x509_hash の定義文には無い（redirect_uri との突合は要求しない）。
   * **既定は変えない**——`clientIdPrefix` 未指定時は従来どおり `x509_san_dns`。実機
   * Multipaz で通っている提示経路に影響させないため、x509_hash は明示指定でのみ使う。
   * 旧 `signed` 引数は後方互換のため残すが、prefix から導出するのが正。
   */
  async createRequest({ specs, sessionId, linkTo, protocol = 'annex-d', transport, responseUri, responseUriBase, purpose, rpName, clientIdPrefix = null, signed = null } = {}) {
    await this._ensurePki();
    const nonce = rand();
    const dcql_query = buildDcql(specs);
    const transactionId = randId();
    // この要求専用の応答暗号鍵（上の newEphemeralEncKey を参照）
    const { encPem, encJwk } = newEphemeralEncKey();

    if (protocol === 'annex-c') {
      if (dcql_query.credentials.some((q) => q.format !== 'mso_mdoc')) {
        throw new Error('Annex C (org-iso-mdoc) supports mdoc only');
      }
      // The Annex C verify path handles exactly one DeviceResponse; a multi-spec
      // request would silently verify only credentials[0]. Reject it instead.
      if (dcql_query.credentials.length > 1) {
        throw new Error('Annex C (org-iso-mdoc) supports a single credential per request; use Annex D for multi-credential');
      }
      const nonceBytes = randomBytes(16);
      const encInfo = buildEncryptionInfo({ nonce: nonceBytes, recipientCoseKey: coseKeyFromJwk(encJwk) });
      const base64EncryptionInfo = b64url(cborEncode(encInfo));
      const transcript = annexCSessionTranscript({ base64EncryptionInfo, serializedOrigin: this.origin });
      await this.store.set(`vp:${transactionId}`, {
        protocol: 'annex-c', nonce, dcql: dcql_query, transcript, base64EncryptionInfo, encPem,
        sessionId: sessionId ?? transactionId, linkTo,
      });
      // 仕様準拠の wire（issue #13）: data は {deviceRequest, encryptionInfo} の2メンバーのみ。
      // 要求項目は DCQL でなく 18013-5 DeviceRequest（ItemsRequest）で運び、readerAuth
      // （COSE_Sign1・x5chain=pki/reader）で要求と origin/暗号鍵を Reader 署名に束縛する。
      // DCQL は内部の検証簿記（dcqlSatisfied）にのみ使う。
      const q = dcql_query.credentials[0];
      const elements = {};
      for (const c of q.claims || []) {
        const [ns, el] = c.path;
        (elements[ns] ??= {})[el] = !!c.intent_to_retain;
      }
      const deviceRequest = buildDeviceRequest({
        docType: q.meta.doctype_value, elements, sessionTranscriptBytes: transcript,
        readerKeyPem: this.readerKeyPem, readerCertDer: this.readerCertDer, readerCaDer: this.readerCaDer,
      });
      const request = {
        deviceRequest: b64url(deviceRequest),
        encryptionInfo: base64EncryptionInfo, // ["dcapi",{nonce,recipientPublicKey:COSE_Key}]
      };
      return { transactionId, request, origin: this.origin };
    }

    // ---- Annex D : OID4VP / HAIP over DC API (JWE) ----
    const thumbprint = await calculateJwkThumbprint(encJwk);

    if (transport === 'redirect') {
      // OID4VP over HTTPS redirects (no DC API): mdoc MUST use direct_post.jwt.
      const respUri = responseUri || `${responseUriBase}/${transactionId}`;
      // **prefix を決めてから client_id と署名の有無が決まる**（上の JSDoc 参照）。
      // 証明書が無ければ x509_san_dns/x509_hash は名乗れないので redirect_uri へ落ちる——
      // 証明書無しで名乗るとウォレットは client_id と照合できず正しく拒否する。
      // **既定は x509_san_dns のまま**（clientIdPrefix 未指定時。x509_hash は明示指定のみ）。
      const canSign = !!(this.rpKeyPem && this.rpCertDer);
      let prefix = clientIdPrefix ?? (signed === false ? 'redirect_uri' : 'x509_san_dns');
      if ((prefix === 'x509_san_dns' || prefix === 'x509_hash') && !canSign) prefix = 'redirect_uri';
      const signedReq = prefix === 'x509_san_dns' || prefix === 'x509_hash';
      // x509_san_dns の client_id は**証明書の dNSName SAN と完全一致**する必要がある。
      // origin のホスト名を使う（gen-pki.sh が同じ名前を SAN に入れている）。
      // x509_hash は**同じ RP 証明書**（pki/verifier/rp.crt）を使うが、client_id は
      // SAN でなく「DER エンコードされた証明書の SHA-256 を base64url エンコードした値」
      // （§5.9.3 原文・上の JSDoc 参照）。SAN 一致チェックの代わりにハッシュ一致になる。
      const clientId = prefix === 'x509_san_dns'
        ? `x509_san_dns:${new URL(this.origin).hostname}`
        : prefix === 'x509_hash'
          ? `x509_hash:${createHash('sha256').update(Buffer.from(this.rpCertDer)).digest('base64url')}`
          : `redirect_uri:${respUri}`;
      const transcript = oid4vpRedirectSessionTranscript({ clientId, responseUri: respUri, nonce });
      await this.store.set(`vp:${transactionId}`, { protocol: 'annex-d', transport: 'redirect', clientId, nonce, dcql: dcql_query, transcript, encPem, sessionId: sessionId ?? transactionId, linkTo, signed: signedReq, clientIdPrefix: prefix });
      const request = {
        // **リダイレクト経路では署名の有無によらず client_id を必ず載せる**
        // （2026-08-26・conformance suite が2度検出）。
        // 一度「unsigned なら省く」と直したが**それは DC API 限定の規定**だった——
        // 「The client_id parameter MUST be omitted in unsigned requests」は
        // Appendix A（DC API）の文で、そちらは origin をプラットフォームが主張するので
        // RP 識別子が要らない。**HTTPS リダイレクトには origin の主張者がいない**ので
        // client_id が唯一の RP 識別手段で、`redirect_uri` prefix（§5.10）がまさに
        // そのために「client_id = redirect_uri:<response_uri>」を定めている。
        // 省くと suite の EnsureClientIdMatchesResponseUri が落ちる。
        // **経路ごとに規定が違うものを片方の文言で統一しない。**
        client_id: clientId,
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',     // encrypted response posted to response_uri
        response_uri: respUri,
        nonce,
        dcql_query,
        client_metadata: this.clientMetadata(encJwk),
        // **RP 名はデモ拡張**（client_metadata は閉じた集合で `client_name` は
        // 「MUST be ignored」＝入れても機能しない。clientMetadata() 参照）。
        // **明示的に渡されたときだけ載せる**——既定値まで載せると素の要求が常に
        // 「未知パラメータあり」になる。シナリオは見せ場なので載せ、通常の提示は
        // 仕様どおりの形にして、ウォレットは response_uri のホスト名を出す。
        // 仕様上の正攻法は `verifier_info`（RP 属性証明・署名付き）＝issue #39。
        ...(rpName ? { rp_name: rpName } : {}),
        // demo extension for the consent screen (OID4VP 1.0 DCQL has no per-credential
        // purpose field; production would use transaction_data). Redirect transport only —
        // our own web wallet renders it; native wallets never see it.
        ...(purpose ? { purpose } : {}),
      };
      return { transactionId, request };
    }

    const transcript = annexDSessionTranscript({ origin: this.origin, nonce, jwkThumbprint: thumbprint });
    // OID4VP 1.0 / DC API: 提示の audience は **必ず `origin:` を前置したオリジン**
    // （unsigned 要求では client_id は送らず、ウォレットがプラットフォーム主張の origin から
    // web-origin スキームで導出する）。SD-JWT の KB-JWT `aud` はこの値になる。
    // client_id（x509_san_dns:…）を期待すると実機で必ず aud mismatch になる（2026-08-07）。
    // mdoc は SessionTranscript が origin/nonce/鍵拇印を束ねるため影響を受けない＝
    // mdoc だけ通って SD-JWT だけ落ちる、という切り分けにくい形で出た。
    const expectedAud = dcApiAud(this.origin);
    await this.store.set(`vp:${transactionId}`, { protocol: 'annex-d', nonce, dcql: dcql_query, transcript, expectedAud, encPem, sessionId: sessionId ?? transactionId, linkTo });

    const request = {
      protocol: 'openid4vp',
      // OID4VP 1.0 (DC API): 「The `client_id` parameter MUST be omitted in unsigned
      // requests. The Wallet MUST ignore any `client_id` parameter that is present in
      // an unsigned request.」= 送る側は省略必須／受け側は無視必須。我々は
      // x509_san_dns:… を送っており非準拠だった（Multipaz は規定どおり無視していたので
      // 動いてはいた。2026-08-07 修正）。RP 認証が要るなら unsigned をやめて
      // signed request (JAR) にするのが筋で、client_id を足すことではない。
      // 予約 prefix の `origin:` を代わりに入れるのも不可（Wallet は受理してはならない）。
      response_type: 'vp_token',
      response_mode: 'dc_api.jwt',           // encrypted response over DC API
      nonce,
      origin: this.origin,
      dcql_query,
      // **2箇所に書かない**——以前ここだけインラインで重複定義していたため、
      // リダイレクト側を直しても DC API 側が古いままになりうる形だった
      client_metadata: this.clientMetadata(encJwk),
    };
    return { transactionId, request };
  }

  /** Decrypt + verify the vp_token; check DCQL; record/compare holder for linking. */
  async verifyResponse({ transactionId, encryptedResponse }) {
    await this._ensurePki();
    const session = await this.store.get(`vp:${transactionId}`);
    if (!session) return { valid: false, errors: ['unknown transaction'] };
    const errors = [];
    // **復号鍵はその取引のもの**（要求ごとの一時鍵）。`encPem` を持たないのは
    // この変更より前に作られた取引なので、従来の固定鍵で開く（保有中の提示を壊さない）。
    const sessEncPem = session.encPem ?? this.encPrivatePem;
    const sessEncPrivJwk = session.encPem
      ? createPrivateKey(session.encPem).export({ format: 'jwk' })
      : this.encPrivJwk;

    // ---- Annex C : HPKE-open the org-iso-mdoc DeviceResponse ----
    if (session.protocol === 'annex-c') {
      // 実機ウォレットは base64url(CBOR(["dcapi",{enc,cipherText}])) を返す（仕様形）。
      // 自前 wallet の旧オブジェクト形も decodeAnnexCResponse が受理する。
      // 「形式が読めない」と「復号できない」は原因が全く違うので段階を分けて報告する
      // （実機デバッグで一度に切り分かるように）。
      let parsed;
      try { parsed = decodeAnnexCResponse(encryptedResponse); }
      catch (e) { return { valid: false, errors: ['Annex C 応答の形式が不正: ' + e.message] }; }
      let deviceResponse;
      try {
        const suite = hpkeSuite();
        const recipientKey = await suite.kem.importKey('jwk', { ...sessEncPrivJwk, key_ops: ['deriveBits'] }, false);
        deviceResponse = await annexCOpen({ suite, recipientKey, enc: parsed.enc, cipherText: parsed.cipherText, info: session.transcript });
      } catch (e) {
        // 構造は仕様どおり＝残る原因は受信鍵の不一致か SessionTranscript の不一致
        return { valid: false, errors: [`HPKE 復号に失敗（応答の構造は正常・受信鍵か SessionTranscript の不一致）: ${e.message}`] };
      }
      const q = session.dcql.credentials[0];
      const anchors = await this._anchors();
      const r = verifyDeviceResponse(deviceResponse,
        { trustedIacaDer: anchors.issuer, sessionTranscript: session.transcript, expectedDocType: q.meta.doctype_value });
      if (!r.valid) errors.push(`${q.id}: ${r.errors.join(';')}`);
      if (!satisfies(q, r.claims || {})) errors.push(`${q.id}: DCQL not satisfied`);
      if (this.statusResolver && r.status) {
        try { const st = await verifyStatus(r.status, this.statusResolver, { trustedCas: anchors.all }); if (st.revoked) errors.push(`${q.id}: credential revoked`); }
        catch (e) { errors.push(`${q.id}: status check failed: ${e.message}`); }
      }
      const raw = rawVpRepr({ format: 'mso_mdoc', bytes: deviceResponse });
      return { valid: errors.length === 0, results: [{ dcqlId: q.id, claims: r.claims, holder: r.holder, raw }], linkedSameHolder: null, errors };
    }

    // ---- Annex D : JWE-decrypt the OID4VP vp_token ----
    let payload;
    try { payload = await decryptResponse(encryptedResponse, sessEncPem); }
    catch (e) { return { valid: false, errors: ['response decryption failed: ' + e.message] }; }

    const vpToken = payload.vp_token || {};
    const results = [];
    let holder;
    // presence is set-aware: with credential_sets, the holder answers ONE option
    // per set (e.g. mdoc OR SD-JWT of the same document) — absent alternatives
    // are fine as long as each required set has one fully-presented option.
    errors.push(...missingPresentations(session.dcql, Object.keys(vpToken).filter((id) => vpToken[id]?.[0])));
    const anchors = await this._anchors();
    // 適合テスト専用の迂回路（#42・src/features.mjs 参照）。既定 false＝従来どおり fail-closed。
    // **読めなかったことを黙って「既定」にしない**——`readFeatures` は KV が読めないと
    // 既定値へ落ちるので、有効にしたつもりの迂回路が無言で無効になる（2026-08-27 に
    // conformance 実行で実際に「設定画面はチェック済みなのに検証は fail-closed」になり、
    // 原因の切り分けに時間を使った）。判定に使った値を結果へ載せて見えるようにする
    const feats = await readFeatures(this.store, { force: true });
    const trustLeafDirectly = feats.verifier_trust_presented_jwk === true;
    // **鍵がトークンに入っていない相手のための外部指定鍵**（適合テスト専用）。
    // conformance suite の SD-JWT VC はヘッダが `{alg, typ}` だけで x5c も jwk も kid も
    // 無く、鍵は試験の設定で渡される前提になっている。迂回路のときだけ使う
    const directJwk = trustLeafDirectly
      ? await this.store.get('vcfg:trust_jwk').catch(() => null) : null;
    for (const q of session.dcql.credentials) {
      const presented = vpToken[q.id]?.[0];
      if (!presented) continue; // required-but-missing already reported above
      let r;
      if (q.format === 'mso_mdoc') {
        r = verifyDeviceResponse(new Uint8Array(Buffer.from(presented, 'base64url')),
          { trustedIacaDer: anchors.issuer, sessionTranscript: session.transcript, expectedDocType: q.meta.doctype_value });
      } else {
        r = await verifySdJwtPresentation(presented,
          { trustedIssuerCaDer: anchors.sdjwt, trustLeafDirectly, directJwk,
            nonce: session.nonce,
            // DC API は origin:<origin>（保存済み）／HTTPS リダイレクトは client_id
            aud: session.expectedAud || session.clientId || this.clientId });
        r.holder = r.cnf?.jwk;
      }
      if (!r.valid) errors.push(`${q.id}: ${r.errors.join(';')}`);
      if (!satisfies(q, r.claims || {})) errors.push(`${q.id}: DCQL not satisfied`);
      if (this.statusResolver && r.status) {
        try {
          const st = await verifyStatus(r.status, this.statusResolver, { trustedCas: anchors.all });
          if (st.revoked) errors.push(`${q.id}: credential revoked`);
        } catch (e) { errors.push(`${q.id}: status check failed: ${e.message}`); }
      }
      if (r.holder) holder = r.holder;
      const raw = rawVpRepr({ format: q.format, wire: presented });
      results.push({ dcqlId: q.id, claims: r.claims, holder: r.holder, raw });
    }

    // Cross-credential holder comparison within THIS response: null when fewer than
    // two credentials carried a holder key; otherwise whether all keys match.
    // Not an error by itself — a multi-credential request may legitimately carry
    // another subject's credential (e.g. a guardian wallet holding a child's 住民票),
    // so the scenario/consumer layer decides what "same wallet" means for it.
    const holderIds = results.map((r) => r.holder && holderId(r.holder)).filter(Boolean);
    const sameHolderAcrossCreds = holderIds.length >= 2 ? new Set(holderIds).size === 1 : null;

    // session linking: same holder across the linked sequence
    let linkedSameHolder = null;
    if (session.linkTo) {
      const prior = await this.store.get(`holder:${session.linkTo}`);
      linkedSameHolder = prior != null && holder != null && prior === holderId(holder);
      if (!linkedSameHolder) errors.push('linked presentation is a different holder');
    }
    // record the holder handle only for VALID presentations — an invalid one must
    // never (re)bind the session's holder for later linked steps
    if (holder && errors.length === 0) await this.store.set(`holder:${session.sessionId}`, holderId(holder), 1800);

    return { valid: errors.length === 0, results, sameHolderAcrossCreds, linkedSameHolder, errors };
  }
}
