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

// --- Base64 helpers ---
const b64ToBuffer = (b64) => Buffer.from(b64, "base64");
const bufferToB64 = (buf) => buf.toString("base64");

// --- Cookie helper ---
function getAccessToken(req) {
  return req.cookies.access_token || null;
}

// --- Server key helpers ---
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

  return { privateKey, publicKey, publicJwk };
}

// --- Derive shared key ---
async function deriveSharedKey(clientPublicKeyJwk, serverPrivateKey) {
  const clientPem = jwkToPem(clientPublicKeyJwk);
  const clientPubKey = crypto.createPublicKey({
    key: clientPem,
    format: "pem",
    type: "spki",
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey: serverPrivateKey,
    publicKey: clientPubKey,
  });

  return crypto.createSecretKey(sharedSecret.slice(0, 32)); // AES-256
}

// --- AES-GCM encrypt / decrypt ---
async function encrypt(sharedKey, data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedKey.export(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: bufferToB64(iv),
    ciphertext: bufferToB64(Buffer.concat([encrypted, tag])),
  };
}

async function decrypt(sharedKey, payload) {
  const iv = b64ToBuffer(payload.iv);
  const ciphertextWithTag = b64ToBuffer(payload.ciphertext);
  const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
  const encrypted = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    sharedKey.export(),
    iv
  );
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

// --- GET public key ---
app.get("/api/public-key", async (req, res) => {
  const token = getAccessToken(req);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const { publicJwk } = await getServerKeys();
  res.json({ serverPublicKeyJwk: publicJwk });
});

// --- Secure POST ---
app.post("/api/secure-post", async (req, res) => {
  const token = getAccessToken(req);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const { clientPublicKeyJwk, payload } = req.body;
  if (!clientPublicKeyJwk || !payload)
    return res.status(400).json({ error: "Missing fields" });

  const { privateKey } = await getServerKeys();
  const sharedKey = await deriveSharedKey(clientPublicKeyJwk, privateKey);

  const decryptedData = await decrypt(sharedKey, payload);
  console.log("Decrypted data from client:", decryptedData);

  const responseData = { data: "สำเร็จนะ", test: ["1", "2"] };
  const encryptedResponse = await encrypt(sharedKey, responseData);
  res.json(encryptedResponse);
});

const PORT = 4000;
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);
