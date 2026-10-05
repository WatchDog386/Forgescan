// Talks to the backend at /api/v1 (Vite forwards it to the backend; see vite.config.js).
// The access token lives in memory only. The backend also sets a refresh cookie, so a page reload
// or an expired access token continues the session until it ends after 30 minutes without activity.

let token = null;
let signedOut = () => {};
let refreshing = null;

export class ApiError extends Error {
  constructor(status, message, otpRequired = false) {
    super(message);
    this.status = status;
    this.otpRequired = otpRequired; // the password was right; the authenticator code is needed next
  }
}

export function onSignedOut(handler) {
  signedOut = handler;
}

export function getToken() {
  return token;
}

// The user's number, read from the token, so the dashboard can tell which incidents are yours.
export function myUserId() {
  try {
    return Number(JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub);
  } catch {
    return null;
  }
}

function send(method, path, body, withToken = true) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (withToken && token) headers.Authorization = `Bearer ${token}`;
  return fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

async function failure(res) {
  let detail;
  try {
    ({ detail } = await res.json());
  } catch {
    // not JSON; fall through
  }
  if (typeof detail === "string") return new ApiError(res.status, detail);
  if (Array.isArray(detail)) return new ApiError(res.status, detail.map((d) => `${d.loc?.at(-1) ?? "value"}: ${d.msg}`).join("; "));
  if (detail?.message) return new ApiError(res.status, detail.message, detail.otp_required === true);
  return new ApiError(res.status, res.status >= 500 ? "The backend is not answering. Is it running?" : `The server answered ${res.status}.`);
}

export async function login(email, password, code) {
  const res = await send("POST", "/auth/login", code ? { email, password, code } : { email, password }, false);
  if (!res.ok) throw await failure(res);
  const session = await res.json();
  token = session.access_token;
  return session;
}

export async function logout() {
  token = null;
  await send("POST", "/auth/logout", undefined, false).catch(() => {});
}

// A new access token from the refresh cookie. Returns the session, or null when the session has ended.
// Throws when the backend cannot be reached, so callers do not mistake an outage for a sign-out.
export function refresh() {
  refreshing ??= (async () => {
    try {
      const res = await send("POST", "/auth/refresh", undefined, false);
      if (res.status === 401) {
        token = null;
        return null;
      }
      if (!res.ok) throw await failure(res);
      const session = await res.json();
      token = session.access_token;
      return session;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

async function request(method, path, body) {
  let res = await send(method, path, body);
  if (res.status === 401) {
    if (!(await refresh())) {
      signedOut();
      throw new ApiError(401, "Your session has ended. Sign in again.");
    }
    res = await send(method, path, body);
  }
  if (!res.ok) throw await failure(res);
  return res.status === 204 ? null : res.json();
}

export const get = (path) => request("GET", path);
export const post = (path, body) => request("POST", path, body ?? {});
export const put = (path, body) => request("PUT", path, body);
export const patch = (path, body) => request("PATCH", path, body);
export const del = (path) => request("DELETE", path);

export async function health() {
  const res = await fetch("/health");
  if (!res.ok) throw await failure(res);
  return res.json();
}
