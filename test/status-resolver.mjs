// テスト用の statusResolver。**資格証が指した URI をそのまま辿る**。
//
// Status List は形式ごとに別のリストで、idx も形式ごとに独立した索引空間になっている
// （issue #25）。`/status-lists/1` を決め打ちすると mdoc の資格証を SD-JWT のリストで
// 判定して取り違えるので、テストでも本番と同じく URI に従う。
//
// app は「アプリ」でも「アプリを返す関数」でもよい（後で宣言される変数を参照する
// 呼び出し側があるため、解決は resolver の実行時まで遅延させる）。
export const statusResolverFor = (app) => async (uri) => {
  const a = typeof app === 'function' ? app() : app;
  let path = '/status-lists/1';
  try { path = new URL(uri).pathname; } catch { /* 相対や空は既定へ */ }
  return (await a.request(path)).text();
};
