// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DiscoveryScope } from "../../api/types";
import { SiteProvider } from "../../site/SiteContext";
import { BRANCH_SITE_ID, DEFAULT_SITE_ID, SITES, installFetch, sensor, type Handler } from "../../test/sites";
import { DiscoveryModal } from "./DiscoveryModal";

const OTHER_SITE_ID = "00000000-0000-0000-0000-0000000c0001";

const SCOPE: DiscoveryScope = {
  enabled: true,
  allowed_networks: ["192.168.50.0/24"],
  networks: [{ network: "192.168.50.0/24", hosts: 254 }],
  max_hosts_per_network: 1024,
  excluded: [],
  ports: [22, 80],
  interval_minutes: null,
  icmp: true,
  reverse_dns: true,
  timeout_ms: 500,
  concurrency: 32,
  max_probes_per_second: 100,
};

const GOOD = sensor({ sensor_id: "5e000000-0000-0000-0000-00000000000a", name: "sensor-norte" });
const REVOKED = sensor({ sensor_id: "5e000000-0000-0000-0000-00000000000b", name: "sensor-revocado", status: "revoked" });
const DISABLED = sensor({ sensor_id: "5e000000-0000-0000-0000-00000000000c", name: "sensor-apagado", status: "disabled" });
// Un sensor de otro site que (por error) llegara en la respuesta nunca debe ofrecerse.
const FOREIGN = sensor({
  sensor_id: "5e000000-0000-0000-0000-00000000000d",
  name: "sensor-ajeno",
  site_id: OTHER_SITE_ID,
  site_name: "Otro",
});

let routes: Record<string, Handler>;
let posted: unknown;

beforeEach(() => {
  window.localStorage.clear();
  posted = undefined;
  routes = {
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /sensors": (_init, url) => ({
      body: {
        items: url.searchParams.get("site_id") === BRANCH_SITE_ID ? [GOOD, REVOKED, DISABLED, FOREIGN] : [],
        summary: { total: 0, pending: 0, online: 0, offline: 0, stale: 0, disabled: 0, revoked: 0 },
      },
    }),
    [`GET /sites/${BRANCH_SITE_ID}/networks`]: () => ({
      body: {
        items: [
          { network_id: "n1", site_id: BRANCH_SITE_ID, cidr: "10.20.0.0/24", name: "Oficina", enabled: true, host_count: 254, created_at: "", updated_at: "" },
          { network_id: "n2", site_id: BRANCH_SITE_ID, cidr: "10.21.0.0/24", name: null, enabled: false, host_count: 254, created_at: "", updated_at: "" },
        ],
      },
    }),
    [`GET /sites/${DEFAULT_SITE_ID}/networks`]: () => ({ body: { items: [] } }),
    "POST /console/discovery/jobs": (init) => {
      posted = JSON.parse(String(init.body));
      return { status: 409, body: { error: { code: "discovery_busy", message: "busy" } } };
    },
  };
  installFetch(routes);
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderModal() {
  return render(
    <SiteProvider>
      <DiscoveryModal
        scope={SCOPE}
        activeJobs={[]}
        canAdminister
        adminReason={undefined}
        onClose={() => undefined}
        onShowDevices={() => undefined}
        onChanged={() => undefined}
      />
    </SiteProvider>,
  );
}

describe("DiscoveryModal con sites y sensores", () => {
  it("en el site por defecto ofrece el servidor local con DISCOVERY_ALLOWED_NETWORKS", async () => {
    renderModal();
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    const siteSelect = await within(dialog).findByLabelText("Site");
    await waitFor(() => expect(siteSelect).toHaveValue(DEFAULT_SITE_ID));
    expect(within(dialog).getByLabelText("Servidor local")).toBeChecked();
    expect(within(dialog).getByLabelText("Red a analizar")).toHaveValue("192.168.50.0/24");
    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));
    await waitFor(() =>
      expect(posted).toEqual({ target: "192.168.50.0/24", site_id: DEFAULT_SITE_ID, execution_target: "local" }),
    );
  });

  it("en otro site solo permite sensores de ESE site no revocados ni deshabilitados", async () => {
    renderModal();
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    const siteSelect = await within(dialog).findByLabelText("Site");
    // El archivado no se ofrece.
    expect(Array.from((siteSelect as HTMLSelectElement).options).map((o) => o.textContent)).toEqual([
      "Principal (por defecto)",
      "Sucursal Norte",
    ]);
    fireEvent.change(siteSelect, { target: { value: BRANCH_SITE_ID } });

    // Sin servidor local fuera del site por defecto.
    expect(within(dialog).queryByLabelText("Servidor local")).not.toBeInTheDocument();
    expect(within(dialog).getByLabelText("Sensor del site")).toBeChecked();
    const sensorSelect = (await within(dialog).findByLabelText("Sensor")) as HTMLSelectElement;
    expect(Array.from(sensorSelect.options).map((o) => o.value)).toEqual([GOOD.sensor_id]);
    expect(within(dialog).queryByText(/sensor-ajeno/)).not.toBeInTheDocument();
    expect(within(dialog).queryByText(/sensor-revocado/)).not.toBeInTheDocument();

    // Solo las redes habilitadas del site.
    const network = (await within(dialog).findByLabelText("Red a analizar")) as HTMLSelectElement;
    expect(Array.from(network.options).map((o) => o.value)).toEqual(["10.20.0.0/24"]);

    fireEvent.click(within(dialog).getByRole("button", { name: "Iniciar" }));
    await waitFor(() =>
      expect(posted).toEqual({
        target: "10.20.0.0/24",
        site_id: BRANCH_SITE_ID,
        execution_target: "sensor",
        sensor_id: GOOD.sensor_id,
      }),
    );
    expect(await within(dialog).findByText("Ya hay un descubrimiento en cola o en curso para esa red.")).toBeInTheDocument();
  });

  it("sin sensores utilizables en el site no deja iniciar", async () => {
    routes["GET /sensors"] = () => ({
      body: { items: [REVOKED, FOREIGN], summary: { total: 0, pending: 0, online: 0, offline: 0, stale: 0, disabled: 0, revoked: 0 } },
    });
    renderModal();
    const dialog = screen.getByRole("dialog", { name: "Iniciar descubrimiento" });
    fireEvent.change(await within(dialog).findByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    expect(await within(dialog).findByText(/no tiene sensores disponibles/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Iniciar" })).toBeDisabled();
  });
});
