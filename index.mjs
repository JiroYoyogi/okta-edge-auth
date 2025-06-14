// 標準モジュール
import crypto from "crypto";
import cookie from "cookie";
// 外部モジュール（npm install）
import querystring from "querystring";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";

// https://trial-12345.okta.com/oauth2/default
const OKTA_ISSUER = "";
const CLIENT_ID = "";
// https://12345.cloudfront.net
const CLOUD_FRONT_DOMAIN = "";
const CLIENT_SECRET = "";

// 公開鍵
const JWKS_URL = `${OKTA_ISSUER}/v1/keys`; 
const TOKEN_ENDPOINT = `${OKTA_ISSUER}/v1/token`;
const LOGOUT_ENDPOINT = `${OKTA_ISSUER}/v1/logout`;
const REDIRECT_URI = `${CLOUD_FRONT_DOMAIN}/callback`;
const REDIRECT_URI_LOGOUT = `${CLOUD_FRONT_DOMAIN}/`;

let cachedJWKS = null;
let cachedExpireAt = 0;

// JWKSフェッチ & キャッシュ
async function fetchJWKS() {
  const res = await fetch(JWKS_URL);
  const cacheControl = res.headers.get("cache-control") || "";
  const maxAgeMatch = cacheControl.match(/max-age=(\\d+)/);
  // 第二引数はparseInt("08")などの場合に10進数と解釈させるため
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 3600;
  cachedExpireAt = Date.now() + maxAge * 1000;
  cachedJWKS = await res.json();
}

export const handler = async (event) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  const cookies = cookie.parse(headers.cookie?.[0]?.value || "");

  // ディレクトリインデックス
  if (request.uri.endsWith("/")) {
    request.uri += "index.html";
  } else if (!request.uri.includes(".")) {
    request.uri += "/index.html";
  }

  const idToken = cookies["ID_TOKEN"];
  // IDトークンが無ければ未ログイン
  if (!idToken) {
    return redirectToLogin(request.uri);
  }

  // JWKSのキャッシュをチェック。リクエストの度に取得すると辛い
  if (!cachedJWKS || cachedExpireAt < Date.now()) {
    // 無ければ取得して変数に保存してキャッシュ
    await fetchJWKS();
  }
  // 第二引数は header は取得するため
  const decoded = jwt.decode(idToken, { complete: true });
  const jwk = cachedJWKS.keys.find((k) => k.kid === decoded.header.kid);
  const pem = jwkToPem(jwk);

  // IDトークン検証
  try {
    jwt.verify(idToken, pem, {
      algorithms: ["RS256"],
      issuer: OKTA_ISSUER,
      audience: CLIENT_ID,
    });
  } catch (err) {
    console.log("ID Token verification error:", err);
    return redirectToLogin(request.uri);
  }

  return request;
}