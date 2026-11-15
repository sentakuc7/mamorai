/**
 * LLM provider abstraction. All providers speak the same minimal chat + tool-calling contract.
 * openrouter / ollama use the OpenAI-compatible API; anthropic uses the Messages API.
 */
import { fetch as ufetch } from "undici";
import type { AppConfig } from "../config/index.js";

export type Role = "system" | "user" | "assistant" | "tool";
export interface ToolCall { id: string; name: string; args: Record<string, unknown> }
export interface ChatMessage {
  role: Role;
  content: string | null;
  images?: { mime: string; attachment_id?: number; data?: string }[]; // user: 画像添付（data は送信直前に attachments から解決）
  tool_calls?: ToolCall[];   // assistant
  tool_call_id?: string;     // tool
  name?: string;             // tool
}
export interface ToolDef { name: string; description: string; parameters: Record<string, unknown> }
export interface ChatResult { message: ChatMessage; usage: { input: number; output: number }; model: string; finish: string; raw?: unknown }

export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  chat(messages: ChatMessage[], tools: ToolDef[], opts?: { maxTokens?: number; temperature?: number; signal?: AbortSignal }): Promise<ChatResult>;
}

class HttpError extends Error { constructor(public status: number, msg: string) { super(msg); } }

async function postJson(url: string, body: unknown, headers: Record<string, string>, signal?: AbortSignal): Promise<any> {
  const res = await ufetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body), signal: signal ?? AbortSignal.timeout(180_000) });
  const text = await res.text();
  let json: any; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) throw new HttpError(res.status, `${url} -> ${res.status}: ${text.slice(0, 500)}`);
  return json;
}

// ---------------- OpenAI-compatible (OpenRouter, Ollama) ----------------
export class OpenAICompatProvider implements LlmProvider {
  constructor(public readonly name: string, private baseUrl: string, public readonly model: string, private apiKey?: string, private extraHeaders: Record<string, string> = {}, private fallbackModel?: string) {}

  private toWire(messages: ChatMessage[]) {
    return messages.map((m) => {
      if (m.role === "assistant" && m.tool_calls?.length) {
        return { role: "assistant", content: m.content ?? "", tool_calls: m.tool_calls.map((t) => ({ id: t.id, type: "function", function: { name: t.name, arguments: JSON.stringify(t.args) } })) };
      }
      if (m.role === "tool") return { role: "tool", tool_call_id: m.tool_call_id, name: m.name, content: m.content ?? "" };
      if (m.role === "user" && m.images?.some((i) => i.data)) return { role: "user", content: [{ type: "text", text: m.content ?? "" }, ...m.images.filter((i) => i.data).map((i) => ({ type: "image_url", image_url: { url: `data:${i.mime};base64,${i.data}` } }))] };
      return { role: m.role, content: m.content ?? "" };
    });
  }

  async chat(messages: ChatMessage[], tools: ToolDef[], opts: { maxTokens?: number; temperature?: number; signal?: AbortSignal } = {}): Promise<ChatResult> {
    const body: any = {
      model: this.model,
      messages: this.toWire(messages),
      temperature: opts.temperature ?? 0.2,
      max_tokens: opts.maxTokens ?? 4096,
    };
    if (tools.length) { body.tools = tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })); body.tool_choice = "auto"; }
    if (this.name === "openrouter" && this.fallbackModel) body.models = [this.model, this.fallbackModel];
    const headers: Record<string, string> = { ...this.extraHeaders };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    const json = await postJson(`${this.baseUrl.replace(/\/$/, "")}/chat/completions`, body, headers, opts.signal);
    const choice = json.choices?.[0];
    if (!choice) throw new Error(`no choices in response: ${JSON.stringify(json).slice(0, 300)}`);
    const m = choice.message ?? {};
    const tool_calls: ToolCall[] = (m.tool_calls ?? []).map((t: any, i: number) => {
      let args: Record<string, unknown> = {};
      try { args = typeof t.function?.arguments === "string" ? JSON.parse(t.function.arguments || "{}") : (t.function?.arguments ?? {}); } catch { args = { _raw: t.function?.arguments }; }
      return { id: t.id ?? `call_${Date.now()}_${i}`, name: t.function?.name, args };
    });
    return {
      message: { role: "assistant", content: m.content ?? null, tool_calls: tool_calls.length ? tool_calls : undefined },
      usage: { input: json.usage?.prompt_tokens ?? 0, output: json.usage?.completion_tokens ?? 0 },
      model: json.model ?? this.model,
      finish: choice.finish_reason ?? "stop",
    };
  }
}

// ---------------- Anthropic Messages API ----------------
export class AnthropicProvider implements LlmProvider {
  readonly name = "anthropic";
  constructor(public readonly model: string, private apiKey: string, private baseUrl = "https://api.anthropic.com") {}

  async chat(messages: ChatMessage[], tools: ToolDef[], opts: { maxTokens?: number; temperature?: number; signal?: AbortSignal } = {}): Promise<ChatResult> {
    const system = messages.filter((m) => m.role === "system").map((m) => m.content ?? "").join("\n\n");
    const wire: any[] = [];
    for (const m of messages) {
      if (m.role === "system") continue;
      if (m.role === "user") wire.push(m.images?.some((i) => i.data) ? { role: "user", content: [{ type: "text", text: m.content ?? "" }, ...m.images.filter((i) => i.data).map((i) => ({ type: "image", source: { type: "base64", media_type: i.mime, data: i.data } }))] } : { role: "user", content: m.content ?? "" });
      else if (m.role === "assistant") {
        const content: any[] = [];
        if (m.content) content.push({ type: "text", text: m.content });
        for (const t of m.tool_calls ?? []) content.push({ type: "tool_use", id: t.id, name: t.name, input: t.args });
        wire.push({ role: "assistant", content });
      } else if (m.role === "tool") {
        const last = wire[wire.length - 1];
        const block = { type: "tool_result", tool_use_id: m.tool_call_id, content: m.content ?? "" };
        if (last && last.role === "user" && Array.isArray(last.content) && last.content[0]?.type === "tool_result") last.content.push(block);
        else wire.push({ role: "user", content: [block] });
      }
    }
    const body: any = { model: this.model, max_tokens: opts.maxTokens ?? 4096, temperature: opts.temperature ?? 0.2, messages: wire };
    if (system) body.system = system;
    if (tools.length) body.tools = tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters }));
    const json = await postJson(`${this.baseUrl}/v1/messages`, body, { "x-api-key": this.apiKey, "anthropic-version": "2023-06-01" }, opts.signal);
    const text = (json.content ?? []).filter((b: any) => b.type === "text").map((b: any) => b.text).join("\n");
    const tool_calls: ToolCall[] = (json.content ?? []).filter((b: any) => b.type === "tool_use").map((b: any) => ({ id: b.id, name: b.name, args: b.input ?? {} }));
    return {
      message: { role: "assistant", content: text || null, tool_calls: tool_calls.length ? tool_calls : undefined },
      usage: { input: json.usage?.input_tokens ?? 0, output: json.usage?.output_tokens ?? 0 },
      model: json.model ?? this.model,
      finish: json.stop_reason ?? "end_turn",
    };
  }
}

export function createProvider(cfg: AppConfig, appUrl: string): LlmProvider {
  switch (cfg.LLM_PROVIDER) {
    case "openrouter":
      if (!cfg.OPENROUTER_API_KEY) throw new Error("OPENROUTER_API_KEY is not set");
      return new OpenAICompatProvider("openrouter", "https://openrouter.ai/api/v1", cfg.OPENROUTER_MODEL, cfg.OPENROUTER_API_KEY, { "HTTP-Referer": appUrl, "X-Title": "MamorAI" }, cfg.OPENROUTER_FALLBACK_MODEL);
    case "ollama":
      return new OpenAICompatProvider("ollama", `${cfg.OLLAMA_URL.replace(/\/$/, "")}/v1`, cfg.OLLAMA_MODEL);
    case "anthropic":
      if (!cfg.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY is not set");
      return new AnthropicProvider(cfg.ANTHROPIC_MODEL, cfg.ANTHROPIC_API_KEY);
  }
}
