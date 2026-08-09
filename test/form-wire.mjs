// 申請フォームを**画面が実際に送る形**へ落とす小道具（テスト専用・`*.test.mjs` ではないので
// npm test には拾われない）。
//
// なぜ要るか: 申請レコードの form は複数選択が配列・同意がオブジェクトだが、ブラウザが
// 送るのは「同名の繰り返し」と `consent_<key>=on` である。オブジェクトのまま
// URLSearchParams に入れると `[object Object]` になり、同意が無いものとして弾かれる。
// **保存形とワイヤ形が違う**ことをテスト側でも取り違えないよう1か所に置く。
export const wireForm = (f) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (Array.isArray(v)) v.forEach((x) => p.append(k, x));
    else if (v && typeof v === 'object') {
      for (const [ck, cv] of Object.entries(v)) if (cv) p.append(`consent_${ck}`, 'on');
    } else p.append(k, String(v));
  }
  return p;
};

/** 同じ変換を FormData（添付つきの multipart 送信）へ。 */
export const setWire = (fd, f) => {
  for (const [k, v] of wireForm(f)) fd.append(k, v);
  return fd;
};
