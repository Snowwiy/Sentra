import { describe, expect, it } from "vitest";
import { backoffMs, BUFFER_SIZE, initialModel, liveReducer, streamUrl } from "./liveStream";

describe("liveReducer", () => {
  it("maps server states and keeps the cursor", () => {
    let model = liveReducer(initialModel(), {
      type: "status",
      state: "catching_up",
      channels: ["detection", "siem", "bogus"],
      id: "d1-a0-i0-s0",
    });
    expect(model.state).toBe("catching_up");
    expect(model.channels).toEqual(["detection", "siem"]);
    model = liveReducer(model, { type: "status", state: "live", id: null });
    expect(model.state).toBe("connected");
    expect(model.lastEventId).toBe("d1-a0-i0-s0");
    model = liveReducer(model, { type: "status", state: "degraded", reason: "backlog_skipped", id: null });
    expect(model).toMatchObject({ state: "degraded", reason: "backlog_skipped" });
  });

  it("keeps a bounded ring buffer, newest first, and counts per channel", () => {
    let model = initialModel();
    for (let i = 0; i < BUFFER_SIZE + 50; i += 1) {
      model = liveReducer(model, { type: "item", channel: "siem", data: { id: String(i) }, id: `d0-a0-i0-s${i}`, at: i });
    }
    expect(model.items).toHaveLength(BUFFER_SIZE);
    expect(model.items[0]?.data.id).toBe(String(BUFFER_SIZE + 49));
    expect(model.counts.siem).toBe(BUFFER_SIZE + 50);
    expect(model.lastEventId).toBe(`d0-a0-i0-s${BUFFER_SIZE + 49}`);
  });

  it("tracks reconnecting and disconnected", () => {
    let model = liveReducer(initialModel(), { type: "reconnecting", reason: "network" });
    expect(model.state).toBe("reconnecting");
    model = liveReducer(model, { type: "closed", reason: "session_ended" });
    expect(model.state).toBe("disconnected");
    expect(liveReducer(model, { type: "open" }).state).toBe("connecting");
  });

  it("builds the stream URL and backs off", () => {
    expect(streamUrl(undefined, null)).toBe("/api/v1/live/stream");
    expect(streamUrl("s1", "d1-a2-i3-s4")).toBe("/api/v1/live/stream?site_id=s1&resume=d1-a2-i3-s4");
    expect([0, 1, 2, 10].map(backoffMs)).toEqual([2000, 4000, 8000, 60_000]);
  });
});
