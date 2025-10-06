// server-secure.js
import express from "express";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import crypto from "node:crypto";
import cors from "cors";
import "dotenv/config";
import jwkToPem from "jwk-to-pem";

const app = express();
app.use(cookieParser());
app.use(bodyParser.json({ limit: "100mb" }));
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

/**
 * CONFIG
 * - Ensure env: SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY contain base64-encoded JWK JSON
 * - HKDF config must match client
 */
const HKDF_INFO = Buffer.from("ECDH_AES_256_GCM"); // must match FE
const HKDF_SALT = null; // or Buffer.from("some-static-or-rotating-salt") - if used, must match FE

// --- helpers ---
const b64ToBuffer = (b64) => Buffer.from(b64, "base64");
const bufferToB64 = (buf) => buf.toString("base64");

function validateJwk(jwk, { requirePrivate = false } = {}) {
  if (!jwk || typeof jwk !== "object") throw new Error("JWK missing");
  if (!jwk.kty) throw new Error("JWK.kty missing");
  // Support EC (P-256) or OKP (X25519) depending on deployment
  if (jwk.kty === "EC") {
    if (!jwk.crv || !jwk.x) throw new Error("EC JWK missing crv/x");
    if (requirePrivate && !jwk.d) throw new Error("EC JWK missing d");
  } else if (jwk.kty === "OKP") {
    if (!jwk.crv || !jwk.x) throw new Error("OKP JWK missing crv/x");
    if (requirePrivate && !jwk.d) throw new Error("OKP JWK missing d");
  } else {
    throw new Error("Unsupported JWK.kty");
  }
  return true;
}

async function getServerKeys() {
  if (!process.env.SERVER_PRIVATE_KEY || !process.env.SERVER_PUBLIC_KEY) {
    throw new Error("Server keys not set in env");
  }

  const privateJwk = JSON.parse(
    Buffer.from(process.env.SERVER_PRIVATE_KEY, "base64").toString()
  );
  const publicJwk = JSON.parse(
    Buffer.from(process.env.SERVER_PUBLIC_KEY, "base64").toString()
  );

  validateJwk(privateJwk, { requirePrivate: true });
  validateJwk(publicJwk, { requirePrivate: false });

  const privatePem = jwkToPem(privateJwk, { private: true });
  const publicPem = jwkToPem(publicJwk);

  const privateKey = crypto.createPrivateKey({
    key: privatePem,
    format: "pem",
    type: "pkcs8",
  });

  const publicKey = crypto.createPublicKey({
    key: publicPem,
    format: "pem",
    type: "spki",
  });

  return { privateKey, publicKey, publicJwk, privateJwk };
}

/**
 * Derive AES-256-GCM key from shared secret using HKDF-SHA256
 * returns Buffer (32 bytes)
 */
function deriveAesKeyFromSharedSecret(sharedSecret) {
  // sharedSecret: Buffer
  // HKDF - Node's hkdfSync (node 15+) or use crypto.createHmac / custom if unavailable
  const derived = crypto.hkdfSync(
    "sha256",
    HKDF_SALT,
    sharedSecret,
    HKDF_INFO,
    32
  );
  // zero sharedSecret asap
  try {
    sharedSecret.fill(0);
  } catch (e) {}
  return derived; // Buffer 32 bytes
}

async function deriveSharedAesKey(clientPublicKeyJwk, serverPrivateKey) {
  // Validate JWK
  validateJwk(clientPublicKeyJwk, { requirePrivate: false });

  // Import client public to PEM -> KeyObject
  const clientPem = jwkToPem(clientPublicKeyJwk);
  const clientPubKey = crypto.createPublicKey({
    key: clientPem,
    format: "pem",
    type: "spki",
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey: serverPrivateKey,
    publicKey: clientPubKey,
  }); // Buffer

  const aesKey = deriveAesKeyFromSharedSecret(sharedSecret); // Buffer
  return aesKey;
}

// AES-GCM encrypt/decrypt using raw key buffer
function encryptWithAesKeyBuffer(aesKeyBuffer, data, aad = null) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKeyBuffer, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));

  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // clear plaintext
  plaintext.fill(0);

  return {
    iv: bufferToB64(iv),
    ciphertext: bufferToB64(Buffer.concat([encrypted, tag])),
  };
}

function decryptWithAesKeyBuffer(aesKeyBuffer, payload, aad = null) {
  const iv = b64ToBuffer(payload.iv);
  const ciphertextWithTag = b64ToBuffer(payload.ciphertext);
  if (ciphertextWithTag.length < 16) throw new Error("Invalid ciphertext");
  const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
  const encrypted = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKeyBuffer, iv);
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  const obj = JSON.parse(decrypted.toString("utf8"));

  // clear buffers
  try {
    decrypted.fill(0);
    encrypted.fill(0);
    tag.fill(0);
  } catch (e) {}

  return obj;
}

/**
 * SIMPLE in-memory cache for server public JWK (used by clients).
 * In production, consider rotating keys and cache-control in endpoint.
 */
let publicJwkCache = null;
let publicJwkCacheCreated = 0;
const PUBKEY_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

app.get("/api/public-key", async (req, res) => {
  try {
    // optional: authenticate caller to prevent mass-scrape
    if (
      !publicJwkCache ||
      Date.now() - publicJwkCacheCreated > PUBKEY_CACHE_TTL
    ) {
      const { publicJwk } = await getServerKeys();
      publicJwkCache = publicJwk;
      publicJwkCacheCreated = Date.now();
    }
    // include protocol version + curve info
    res.json({ version: "1", serverPublicKeyJwk: publicJwkCache });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "failed to load public key" });
  }
});

// secure POST
app.post("/api/secure-post", async (req, res) => {
  try {
    // optional: rate limit / auth checks here
    const { clientPublicKeyJwk, payload, version } = req.body;
    if (!clientPublicKeyJwk || !payload) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (version && version !== "1") {
      return res.status(400).json({ error: "Unsupported protocol version" });
    }

    const { privateKey } = await getServerKeys();
    // derive AES key buffer
    const aesKeyBuffer = await deriveSharedAesKey(
      clientPublicKeyJwk,
      privateKey
    );

    // optionally compute AAD (e.g., session token, route) - keep consistent with client if used
    const aad = req.cookies.access_token
      ? `token:${req.cookies.access_token}`
      : null;

    let decryptedData;
    try {
      decryptedData = decryptWithAesKeyBuffer(aesKeyBuffer, payload, aad);
    } catch (err) {
      // zero aesKey
      aesKeyBuffer.fill(0);
      console.warn("Failed to decrypt payload:", err.message);
      return res.status(400).json({ error: "Decrypt failed" });
    }

    console.log("Decrypted data from client:", decryptedData);

    // prepare response
    const responseData = { data: "สำเร็จนะ", serverTime: Date.now() };

    const encryptedResponse = encryptWithAesKeyBuffer(
      aesKeyBuffer,
      responseData,
      aad
    );

    // zero out key
    try {
      aesKeyBuffer.fill(0);
    } catch (e) {}

    res.json(encryptedResponse);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

const PORT = 4000;
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);
