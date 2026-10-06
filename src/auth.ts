import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";

// Basic auth backed by a users.yaml file (git-viewer / email-archive
// pattern). Credentials are validated once via POST {apiPath}/login; the
// client keeps them in localStorage and sends an Authorization: Basic header
// on every API call. The server stays stateless — no sessions, no cookies.
//
// users.yaml (re-read whenever its mtime changes — edits apply without a
// server restart; override the path with the USERS_FILE env var):
//
//   users:
//     alice:
//       password: "alice"                # plain text, or "sha256:<hex>"
//     bob:
//       # echo -n 'bob' | sha256sum      # (-n: no trailing newline)
//       password: "sha256:81b637d8…"
//
// Keeping login/password pairs in the Authorization header is safe over
// HTTPS; the server must never run API auth over plain HTTP in production.

export const apiPath = "/api";

type UserConfig = { password?: string };
type UsersConfig = { users?: Record<string, UserConfig> };

export const usersFile = (): string =>
  process.env.USERS_FILE
    ? path.resolve(process.env.USERS_FILE)
    : path.join(process.cwd(), "users.yaml");

let cache: { mtimeMs: number; config: UsersConfig } | null = null;

const loadUsers = async (): Promise<UsersConfig> => {
  try {
    const stat = await fs.stat(usersFile());
    if (cache?.mtimeMs === stat.mtimeMs) return cache.config;
    const text = await fs.readFile(usersFile(), "utf8");
    const config = (parse(text) ?? {}) as UsersConfig;
    cache = { mtimeMs: stat.mtimeMs, config };
    return config;
  } catch (error) {
    console.error(`[auth] cannot read ${usersFile()}: ${error}`);
    return {};
  }
};

const digest = (value: string): Buffer =>
  crypto.createHash("sha256").update(value).digest();

const passwordMatches = (
  stored: string | undefined,
  given: string,
): boolean => {
  if (!stored) return false;
  const expected = stored.startsWith("sha256:")
    ? Buffer.from(stored.slice(7), "hex")
    : digest(stored);
  if (expected.length !== 32) return false;
  return crypto.timingSafeEqual(expected, digest(given));
};

/** Validate a login/password pair against users.yaml. */
export const checkCredentials = async (
  login: string,
  password: string,
): Promise<boolean> => {
  const { users } = await loadUsers();
  const cfg = users?.[login];
  return !!cfg && passwordMatches(cfg.password, password);
};

/** Parse an Authorization: Basic header into { login, password }, or null. */
export const parseBasicHeader = (
  header: string | undefined,
): { login: string; password: string } | null => {
  const m = /^Basic (.+)$/i.exec(header ?? "");
  if (!m) return null;
  const decoded = Buffer.from(m[1], "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep < 0) return null;
  return { login: decoded.slice(0, sep), password: decoded.slice(sep + 1) };
};
