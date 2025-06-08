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
// https://12345.cloudfront.net/callback
const REDIRECT_URI = "";
const CLIENT_SECRET = "";
// 公開鍵
const JWKS_URL = `${OKTA_ISSUER}/v1/keys`; 
const TOKEN_ENDPOINT = `${OKTA_ISSUER}/v1/token`;
const LOGOUT_ENDPOINT = `${OKTA_ISSUER}/v1/logout`;

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

function redirectToLogin(returnUri) {
  // state ランダムな文字列
  const stateToken = crypto.randomBytes(16).toString("hex");
  // nonce ランダムな文字列
  const nonce = crypto.randomBytes(16).toString("hex");
  // PKCE
  // 1. ランダムな秘密の文字列（クライアント側に保存）
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  // 2. SHA-256でハッシュ値（バイナリ）作成
  const codeVerifierHash = crypto.createHash("sha256").update(codeVerifier).digest();
  // 3. ハッシュ値をbase64urlに変換。URLで使える文字列に変換
  const codeChallenge = Buffer.from(codeVerifierHash).toString("base64url")
  
  const stateObj = {
    // ユーザーがアクセスしようとしているページのURL
    // 全く必須では無いが認証後にリダイレクトさせるためによく埋められてる
    returnUri,
    // state検証用のランダムな文字列
    stateToken,
  };
  const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");

  // 認可リクエストのURL
  const authUrl =
    `${OKTA_ISSUER}/v1/authorize?` +
    querystring.stringify({
      client_id: CLIENT_ID,
      response_type: "code",
      scope: "openid email",
      redirect_uri: REDIRECT_URI,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });

  // ブラウザにcookieをセットした後に authUrl へリダイレクト
  return {
    status: "302",
    headers: {
      location: [{ key: "Location", value: authUrl }],
      // nonce検証するためにブラウザのcookieに保存
      "set-cookie": [
        {
          key: "Set-Cookie",
          value: cookie.serialize("NONCE", nonce, {
            path: "/",
            httpOnly: true,
          }),
        },
        // PKCE検証するためにブラウザのcookieに保存
        {
          key: "Set-Cookie",
          value: cookie.serialize("PKCE", codeVerifier, {
            path: "/",
            httpOnly: true,
          }),
        },
        // state検証するためにブラウザのcookieに保存
        {
          key: "Set-Cookie",
          value: cookie.serialize("STATE", stateToken, {
            path: "/",
            httpOnly: true,
          }),
        },
      ],
    },
  };
}

export const handler = async (event) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  const cookies = cookie.parse(headers.cookie?.[0]?.value || "");

    // Hosted UIからの戻って来たリクエスト
  if (request.uri.startsWith("/callback")) {
    // Hosted UIでログインするとコールバックURLに色々なクエリが追加される
    const query = new URLSearchParams(request.querystring);

    // Hosted UI（Okta）が発行した一時的な短命のチケット
    // トークンと引き換えれる。引き換え時にPKCE検証が行われる
    const code = query.get("code");

    // 認可リクエスト時にくっつけたクエリが返ってくる。改竄されていないか後でチェック
    const state = query.get("state");

    // クッキーに保存してた nonce を取得
    const nonce = cookies["NONCE"];
    // クッキーに保存してた codeVerifier（秘密の文字列）を取得
    const codeVerifier = cookies["PKCE"];
    // クッキーに保存してた state を取得
    const stateTokenFromCookie = cookies["STATE"];

    if (!code || !state || !nonce || !codeVerifier || !stateTokenFromCookie) {
      return callback(null, redirectToLogin("/"));
    }

    const stateJson = Buffer.from(state, "base64url").toString("utf-8");
    const stateObj = JSON.parse(stateJson);

    // state検証
    if (stateObj.stateToken !== stateTokenFromCookie) {
      console.log("CSRFトークン不一致！");
      return callback(null, redirectToLogin("/"));
    }

    // 元ページに戻るURLを取得
    const returnUri = stateObj.returnUri;

    // 認可コードをトークンに交換
    const tokenRes = await fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: querystring.stringify({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: codeVerifier,
        client_secret: CLIENT_SECRET,
      }),
    });
    const tokenJson = await tokenRes.json();
    const idToken = tokenJson.id_token;

    if (!cachedJWKS || cachedExpireAt < Date.now()) await fetchJWKS();
    const decoded = jwt.decode(idToken, { complete: true });
    console.log(decoded);
    const jwk = cachedJWKS.keys.find((k) => k.kid === decoded.header.kid);
    const pem = jwkToPem(jwk);

    try {
      // 受け取ったトークンを検証
      const verified = jwt.verify(idToken, pem, {
        algorithms: ["RS256"],
        issuer: OKTA_ISSUER,
        audience: CLIENT_ID,
      });

      // nonce検証
      // 認可リクエスト時に送った nonceは idTokne に含まれる
      // クッキーに保存してるものと同じか検証
      if (verified.nonce !== nonce) throw new Error("Nonce mismatch");

      // 問題無ければユーザーが元々アクセスしようとしてページにリダイレクト
      return {
        status: "302",
        headers: {
          location: [{ key: "Location", value: returnUri }],
          "set-cookie": [
            // 以降のリクエストではIDトークンを検証したいのでクッキーに保存
            {
              key: "Set-Cookie",
              value: cookie.serialize("ID_TOKEN", idToken, {
                path: "/",
                httpOnly: true,
                secure: true,
              }),
            },
            // nonce検証に使ってたクッキーを削除
            {
              key: "Set-Cookie",
              value: cookie.serialize("NONCE", "", {
                path: "/",
                expires: new Date(0),
              }),
            },
            // PKCE検証に使ってたクッキーを削除
            {
              key: "Set-Cookie",
              value: cookie.serialize("PKCE", "", {
                path: "/",
                expires: new Date(0),
              }),
            },
            // state検証に使ってたクッキーを削除
            {
              key: "Set-Cookie",
              value: cookie.serialize("STATE", "", {
                path: "/",
                expires: new Date(0),
              }),
            },
          ],
        },
      };

    } catch (err) {
      console.err(err);
      return callback(null, redirectToLogin("/"));
    }
  }

  if (request.uri.startsWith("/logout")) {
    const idTokenFromCookie = cookies["ID_TOKEN"];
    return {
      status: "302",
      headers: {
        // ログアウトURLにリクエスト
        // 誰がログアウトするのかIDトークンをクエリに付与
        location: [{ key: "Location", value: `${LOGOUT_ENDPOINT}?id_token_hint=${idTokenFromCookie}` }],
        "set-cookie": [
          // クッキーに保存してたIDトークンを削除
          {
            key: "Set-Cookie",
            value: cookie.serialize("ID_TOKEN", "", {
              path: "/",
              expires: new Date(0), // 期限切れはブラウザから削除される
              httpOnly: true,
              secure: true,
            }),
          },
        ],
      },
    };
  }

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
    console.err("ID Token verification error:", err);
    return redirectToLogin(request.uri);
  }

  return request;
}