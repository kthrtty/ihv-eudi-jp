// **authorization_code の1周で KV を何回叩くかを数える。**
//
//   npm run kv-count                      素の1周・1枚発行
//   MODE=haip npm run kv-count            DPoP 必須（適合テスト相当）
//   CREDS=5 npm run kv-count              1回の Credential Request で5枚
//
// **なぜ要るか**: Cloudflare KV の無料枠は書き込み 1,000回/日。適合テストの
// VCI 全63件で約570回に達したことがあり、**測定を重ねると枠を使い切る**。
// 機能を足したときに1周あたりの書き込みが増えていないかを、ここで先に見る。
//
// store をラップして数えるだけなので**ネットワークにも本番 KV にも触らない**
// （`createApp` の既定は memoryStore）。接頭辞ごとの内訳も出すので、
// どのキー種別が増えたかが分かる。
import { createApp } from '../src/app.mjs';
import { setFeature } from '../src/features.mjs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createHash, randomUUID } from 'node:crypto';
const ISS='https://issuer.ihv.example';
const app=createApp({credentialIssuer:ISS,redirectAllowlist:'https://rp.example/cb'});
const st=app.svc.store; const n={get:0,set:0,del:0};
const byKey={};
for (const k of ['set','del']) { const o=st[k].bind(st); st[k]=async(kk,...a)=>{n[k]++;const p=String(kk).split(':')[0];byKey[p]=(byKey[p]||0)+1;return o(kk,...a);}; }
{ const o=st.get.bind(st); st.get=async(...a)=>{n.get++;return o(...a);}; }
globalThis.__byKey=byKey;
const mode=process.env.MODE||'plain';
if (mode==='haip') { await setFeature(st,'dpop','required'); }
n.get=n.set=n.del=0;
const login=await (await app.request(`${ISS}/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user_id:'u_001'})})).json();
const v='v'.repeat(43), ch=createHash('sha256').update(v).digest('base64url');
const kp=await generateKeyPair('ES256',{extractable:true}); const jwk=await exportJWK(kp.publicKey);
const dpop=async(htu)=>new SignJWT({htm:'POST',htu,jti:randomUUID()})
  .setProtectedHeader({alg:'ES256',typ:'dpop+jwt',jwk}).setIssuedAt().sign(kp.privateKey);
const H=mode==='haip'?{dpop:await dpop(`${ISS}/par`)}:{};
const par=await (await app.request(`${ISS}/par`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...H},
  body:new URLSearchParams({response_type:'code',client_id:'c1',redirect_uri:'https://rp.example/cb',scope:'pid_sdjwt',code_challenge:ch,code_challenge_method:'S256'})})).json();
const ck=`sid=${login.session_id}`;
const html=await (await app.request(`${ISS}/authorize?client_id=c1&request_uri=${encodeURIComponent(par.request_uri)}`,{headers:{cookie:ck}})).text();
const pp=[]; for (const m of html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)){const k=/name="([^"]*)"/.exec(m[0])?.[1],vv=/value="([^"]*)"/.exec(m[0])?.[1]??'';if(k)pp.push([k,vv.replace(/&amp;/g,'&')]);}
const loc=(await app.request(`${ISS}/authorize/consent`,{method:'POST',redirect:'manual',headers:{cookie:ck,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(pp).toString()})).headers.get('location');
const code=new URL(loc).searchParams.get('code');
const T=mode==='haip'?{dpop:await dpop(`${ISS}/token`)}:{};
const tok=await (await app.request(`${ISS}/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...T},
  body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:'https://rp.example/cb',code_verifier:v})})).json();
const nc=(await (await app.request(`${ISS}/nonce`,{method:'POST'})).json()).c_nonce;
const N=Number(process.env.CREDS||1); const proofs=[];
for(let i=0;i<N;i++){const h=await generateKeyPair('ES256',{extractable:true});
  proofs.push(await new SignJWT({aud:ISS,nonce:nc}).setProtectedHeader({alg:'ES256',typ:'openid4vci-proof+jwt',jwk:await exportJWK(h.publicKey)}).setIssuedAt().sign(h.privateKey));}
const C=mode==='haip'?{dpop:await dpop(`${ISS}/credential`)}:{};
const r=await app.request(`${ISS}/credential`,{method:'POST',headers:{'content-type':'application/json',authorization:`${mode==='haip'?'DPoP':'Bearer'} ${tok.access_token}`,...C},
  body:JSON.stringify({credential_configuration_id:'pid_sdjwt',proofs:{jwt:proofs}})});
console.log('  書き込みの内訳:', JSON.stringify(globalThis.__byKey));
console.log(`  MODE=${mode} 発行${N}枚 → HTTP ${r.status} ／ KV: get ${n.get} / set ${n.set} / del ${n.del}  （書き込み計 ${n.set+n.del}）`);
