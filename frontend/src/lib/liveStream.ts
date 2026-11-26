// Live SOC (Fase 7F.7): cliente del stream SSE /api/v1/live/stream.
//
// EventSource envía la cookie de sesión y, al reconectar por su cuenta, la cabecera
// Last-Event-ID con los cursores del último mensaje: el servidor sigue donde se quedó. Si la
// conexión se cierra del todo (error HTTP, red caída largo rato), se reabre con `resume`
// (EventSource nuevo no envía Last-Event-ID) y una espera creciente. Los mensajes se guardan en
// un buffer circular acotado: la memoria del navegador no crece con el tiempo.
import { useEffect, useReducer, useRef } from "react";
import { config } from "../config";

export type LiveState = "connecting" | "connected" | "reconnecting" | "disconnected" | "degraded" | "catching_up";
export type LiveChannel = "detection" | "alert" | "incident" | "siem";

export interface LiveItem {
  key: string;
  channel: LiveChannel;
  data: Record<string, unknown>;
  receivedAt: number;
}

export interface LiveModel {
  state: LiveState;
  reason: string | null;
  channels: LiveChannel[];
  items: LiveItem[];
  counts: Record<LiveChannel, number>;
  lastEventId: string | null;
}

export const BUFFER_SIZE = 200;
const CHANNELS: LiveChannel[] = ["detection", "alert", "incident", "siem"];

export type LiveAction =
  | { type: "open" }
  | { type: "status"; state: string; reason?: string; channels?: string[]; id: string | null }
  | { type: "item"; channel: LiveChannel; data: Record<string, unknown>; id: string | null; at: number }
  | { type: "reconnecting"; reason: string }
  | { type: "closed"; reason: string };

export function initialModel(): LiveModel {
  return {
    state: "connecting",
    reason: null,
    channels: [],
    items: [],
    counts: { detection: 0, alert: 0, incident: 0, siem: 0 },
    lastEventId: null,
  };
}

const SERVER_STATES: Record<string, LiveState> = {
  live: "connected",
  catching_up: "catching_up",
  degraded: "degraded",
};

export function liveReducer(model: LiveModel, action: LiveAction): LiveModel {
  switch (action.type) {
    case "open":
      return { ...model, state: model.state === "disconnected" ? "connecting" : model.state };
    case "status": {
      const state = SERVER_STATES[action.state] ?? model.state;
      const channels = action.channels
        ? (action.channels.filter((c) => (CHANNELS as string[]).includes(c)) as LiveChannel[])
        : model.channels;
      // "degraded" con motivo se mantiene visible hasta el siguiente estado del servidor.
      return { ...model, state, reason: action.reason ?? null, channels, lastEventId: action.id ?? model.lastEventId };
    }
    case "item": {
      const item: LiveItem = {
        key: `${action.channel}:${String(action.data.id ?? "")}:${action.id ?? action.at}`,
        channel: action.channel,
        data: action.data,
        receivedAt: action.at,
      };
      const items = [item, ...model.items].slice(0, BUFFER_SIZE);
      return {
        ...model,
        items,
        counts: { ...model.counts, [action.channel]: model.counts[action.channel] + 1 },
        lastEventId: action.id ?? model.lastEventId,
      };
    }
    case "reconnecting":
      return { ...model, state: "reconnecting", reason: action.reason };
    case "closed":
      return { ...model, state: "disconnected", reason: action.reason };
  }
}

export function streamUrl(siteId: string | undefined, resume: string | null): string {
  const params = new URLSearchParams();
  if (siteId) params.set("site_id", siteId);
  if (resume) params.set("resume", resume);
  const query = params.toString();
  return `${config.apiBaseUrl}/api/v1/live/stream${query ? `?${query}` : ""}`;
}

type SourceFactory = (url: string) => EventSource;

const defaultFactory: SourceFactory = (url) => new EventSource(url, { withCredentials: true });

/** Espera antes de reabrir tras un cierre definitivo: 2, 4, 8... hasta 60 s. */
export function backoffMs(attempt: number): number {
  return Math.min(60_000, 2000 * 2 ** Math.max(0, attempt));
}

export function useLiveStream(siteId: string | undefined, factory: SourceFactory = defaultFactory): LiveModel {
  const [model, dispatch] = useReducer(liveReducer, undefined, initialModel);
  const lastId = useRef<string | null>(null);

  useEffect(() => {
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let stopped = false;

    const parse = (event: MessageEvent<string>): Record<string, unknown> | null => {
      try {
        const value: unknown = JSON.parse(event.data);
        return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
      } catch {
        return null;
      }
    };

    const remember = (event: MessageEvent<string>) => {
      if (event.lastEventId) lastId.current = event.lastEventId;
      return event.lastEventId || null;
    };

    const open = () => {
      if (stopped) return;
      dispatch({ type: "open" });
      const es = factory(streamUrl(siteId, lastId.current));
      source = es;
      es.addEventListener("status", (event) => {
        const data = parse(event as MessageEvent<string>);
        if (!data) return;
        attempt = 0;
        dispatch({
          type: "status",
          state: String(data.state ?? ""),
          reason: typeof data.reason === "string" ? data.reason : undefined,
          channels: Array.isArray(data.channels) ? data.channels.map(String) : undefined,
          id: remember(event as MessageEvent<string>),
        });
      });
      for (const channel of CHANNELS) {
        es.addEventListener(channel, (event) => {
          const data = parse(event as MessageEvent<string>);
          if (!data) return;
          dispatch({ type: "item", channel, data, id: remember(event as MessageEvent<string>), at: Date.now() });
        });
      }
      es.addEventListener("reconnect", (event) => {
        remember(event as MessageEvent<string>);
        // El servidor cierra al cumplir la duración máxima: el navegador reconecta solo.
        dispatch({ type: "reconnecting", reason: "max_duration" });
      });
      es.addEventListener("session_ended", () => {
        // Sesión revocada o caducada: no se reintenta (haría falta volver a entrar).
        stopped = true;
        es.close();
        dispatch({ type: "closed", reason: "session_ended" });
      });
      es.onerror = () => {
        if (stopped) return;
        if (es.readyState === EventSource.CLOSED) {
          es.close();
          dispatch({ type: "closed", reason: "connection_closed" });
          timer = setTimeout(open, backoffMs(attempt++));
        } else {
          dispatch({ type: "reconnecting", reason: "network" });
        }
      };
    };

    open();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      source?.close();
    };
  }, [siteId, factory]);

  return model;
}
