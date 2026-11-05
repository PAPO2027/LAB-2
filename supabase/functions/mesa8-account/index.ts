import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.119.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const secretKeysRaw = Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}";
let secretKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
try {
  const parsed = JSON.parse(secretKeysRaw);
  secretKey = parsed.default || secretKey;
} catch {
  // Fall back to the legacy service-role secret when available.
}
if (!SUPABASE_URL || !secretKey) {
  throw new Error("Supabase server URL or secret key is missing.");
}

const admin = createClient(SUPABASE_URL, secretKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "apikey, content-type, x-mesa8-token",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const CUES = ["wood", "cobalt", "carbon", "phoenix", "emerald", "neon", "solar", "prism"];
const SKINS = ["green", "blue", "purple", "red"];
const PASSWORD_ITERATIONS = 310000;
const SESSION_DAYS = 30;

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: CORS_HEADERS });
}
function normalizeUsername(value: unknown) {
  return String(value ?? "").normalize("NFKC").replace(/\s+/g, " ").trim().toLowerCase();
}
function displayUsername(value: unknown) {
  return String(value ?? "").normalize("NFKC").replace(/\s+/g, " ").trim();
}
function encodeBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function decodeBase64Url(value: string) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function derivePasswordHash(password: string, salt: Uint8Array) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return encodeBase64Url(new Uint8Array(bits));
}
function constantTimeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}
function validateCredentials(usernameInput: unknown, passwordInput: unknown) {
  const username = displayUsername(usernameInput);
  const usernameKey = normalizeUsername(username);
  const password = String(passwordInput ?? "");
  if ([...username].length < 3 || [...username].length > 18 || username.includes("@")) {
    throw new ApiError(400, "El nombre debe tener entre 3 y 18 caracteres y no puede ser un correo.");
  }
  if (password.length < 8 || password.length > 128) {
    throw new ApiError(400, "La contraseña debe tener entre 8 y 128 caracteres.");
  }
  return { username, usernameKey, password };
}
async function createSession(accountId: string) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = encodeBase64Url(bytes);
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { error } = await admin.from("mesa8_sessions").insert({
    account_id: accountId,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });
  if (error) throw error;
  await admin.from("mesa8_sessions").delete().lt("expires_at", new Date().toISOString());
  return token;
}
async function requireAccount(request: Request) {
  const token = request.headers.get("x-mesa8-token") ?? "";
  if (!token || token.length > 200) throw new ApiError(401, "Tu sesión no es válida. Inicia sesión otra vez.");
  const tokenHash = await sha256(token);
  const { data, error } = await admin.from("mesa8_sessions")
    .select("id,account_id,expires_at")
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (error) throw error;
  if (!data) throw new ApiError(401, "Tu sesión expiró. Inicia sesión otra vez.");
  return { sessionId: data.id as string, accountId: data.account_id as string, tokenHash };
}
async function getPlayerData(accountId: string) {
  const [{ data: account, error: accountError }, { data: profile, error: profileError }] = await Promise.all([
    admin.from("mesa8_accounts").select("id,username").eq("id", accountId).single(),
    admin.from("mesa8_profiles")
      .select("wins,losses,coins,played,potted,owned,cue_id,skin,updated_at")
      .eq("account_id", accountId).single(),
  ]);
  if (accountError) throw accountError;
  if (profileError) throw profileError;
  return { username: account.username, account_id: account.id, profile };
}
function safeCounter(value: unknown, field: string) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0 || number > 1000000000) {
    throw new ApiError(400, "Valor no válido para " + field + ".");
  }
  return number;
}
function sanitizeProfile(body: Record<string, unknown>) {
  const ownedInput = Array.isArray(body.owned) ? body.owned : ["wood", "cobalt", "carbon"];
  const owned = [...new Set(ownedInput.filter((item): item is string => typeof item === "string" && CUES.includes(item)))];
  if (!owned.includes("wood")) owned.unshift("wood");
  const cueId = typeof body.cue_id === "string" && CUES.includes(body.cue_id) && owned.includes(body.cue_id)
    ? body.cue_id
    : "wood";
  const skin = typeof body.skin === "string" && SKINS.includes(body.skin) ? body.skin : "red";
  return {
    wins: safeCounter(body.wins, "victorias"),
    losses: safeCounter(body.losses, "derrotas"),
    coins: safeCounter(body.coins, "monedas"),
    played: safeCounter(body.played, "partidas"),
    potted: safeCounter(body.potted, "bolas embocadas"),
    owned,
    cue_id: cueId,
    skin,
    updated_at: new Date().toISOString(),
  };
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: CORS_HEADERS });
  if (request.method !== "POST") return reply(405, { error: "Método no permitido." });

  try {
    const body = await request.json() as Record<string, unknown>;
    const action = String(body.action ?? "");

    if (action === "signup") {
      const { username, usernameKey, password } = validateCredentials(body.username, body.password);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltText = encodeBase64Url(salt);
      const passwordHash = await derivePasswordHash(password, salt);

      const { data: account, error: accountError } = await admin.from("mesa8_accounts")
        .insert({
          username,
          username_key: usernameKey,
          password_salt: saltText,
          password_hash: passwordHash,
        })
        .select("id,username")
        .single();

      if (accountError) {
        if (accountError.code === "23505") throw new ApiError(409, "Ese nombre de usuario ya está ocupado.");
        throw accountError;
      }

      const { error: profileError } = await admin.from("mesa8_profiles").insert({
        account_id: account.id,
        wins: 0,
        losses: 0,
        coins: 120,
        played: 0,
        potted: 0,
        owned: ["wood", "cobalt", "carbon"],
        cue_id: "wood",
        skin: "red",
      });
      if (profileError) {
        await admin.from("mesa8_accounts").delete().eq("id", account.id);
        throw profileError;
      }

      const token = await createSession(account.id);
      const player = await getPlayerData(account.id);
      return reply(201, { token, ...player });
    }

    if (action === "login") {
      const { usernameKey, password } = validateCredentials(body.username, body.password);
      const { data: account, error } = await admin.from("mesa8_accounts")
        .select("id,username,password_salt,password_hash")
        .eq("username_key", usernameKey)
        .maybeSingle();
      if (error) throw error;
      if (!account) throw new ApiError(401, "Nombre de usuario o contraseña incorrectos.");

      const salt = decodeBase64Url(account.password_salt);
      const candidateHash = await derivePasswordHash(password, salt);
      if (!constantTimeEqual(candidateHash, account.password_hash)) {
        throw new ApiError(401, "Nombre de usuario o contraseña incorrectos.");
      }

      const token = await createSession(account.id);
      const player = await getPlayerData(account.id);
      return reply(200, { token, ...player });
    }

    if (action === "get_profile") {
      const { accountId } = await requireAccount(request);
      const player = await getPlayerData(accountId);
      return reply(200, player);
    }

    if (action === "save_profile") {
      const { accountId } = await requireAccount(request);
      const profile = sanitizeProfile(body);
      const { error } = await admin.from("mesa8_profiles")
        .update(profile)
        .eq("account_id", accountId);
      if (error) throw error;
      return reply(200, { ok: true });
    }

    if (action === "logout") {
      const { sessionId } = await requireAccount(request);
      const { error } = await admin.from("mesa8_sessions").delete().eq("id", sessionId);
      if (error) throw error;
      return reply(200, { ok: true });
    }

    return reply(400, { error: "Acción no reconocida." });
  } catch (error) {
    const status = error instanceof ApiError ? error.status : 500;
    const message = error instanceof Error ? error.message : "Error interno.";
    if (status >= 500) console.error("mesa8-account:", message);
    return reply(status, { error: status >= 500 ? "No se pudo completar la operación. Inténtalo más tarde." : message });
  }
});
