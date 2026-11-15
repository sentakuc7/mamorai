export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-Requested-With": "edr-console" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const text = await res.text();
  let data: any = null; try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!res.ok) throw new ApiError(res.status, data?.error ?? `${res.status}`);
  return data as T;
}

export const api = {
  get: <T>(p: string) => req<T>("GET", p),
  post: <T>(p: string, b?: unknown) => req<T>("POST", p, b),
  put: <T>(p: string, b?: unknown) => req<T>("PUT", p, b),
  patch: <T>(p: string, b?: unknown) => req<T>("PATCH", p, b),
  del: <T>(p: string) => req<T>("DELETE", p),
};

export interface User { id: number; email: string; name: string; role: "admin" | "operator" | "viewer"; locale: string; must_change_password: boolean; mfa_enabled?: boolean }

export function fmtTs(s: string | number | Date | null | undefined): string {
  if (s == null || s === "") return "-";
  if (s instanceof Date) return s.toLocaleString("ja-JP", { hour12: false });
  if (typeof s === "number") return new Date(s < 1e12 ? s * 1000 : s).toLocaleString("ja-JP", { hour12: false });
  const d = new Date(/Z|[+-]\d\d:?\d\d$/.test(s) ? s : s.replace(" ", "T") + "Z");
  return isNaN(d.getTime()) ? s : d.toLocaleString("ja-JP", { hour12: false });
}
