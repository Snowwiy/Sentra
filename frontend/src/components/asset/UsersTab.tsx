import type { AccountInfo, LoggedInUser } from "../../api/types";
import { compareBy, listPage, matchesText } from "../../lib/listing";
import { formatDateTime, formatRelative } from "../../lib/format";
import { useListState } from "../../lib/useListState";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../ListControls";
import { EmptyState } from "../StateViews";

const PAGE_SIZE = 50;

function yesNo(value: boolean | null, yes: string, no: string) {
  if (value == null) return <span className="muted">desconocido</span>;
  return value ? yes : no;
}

export function UsersTab({ sessions, accounts }: { sessions: LoggedInUser[]; accounts: AccountInfo[] | undefined }) {
  const list = useListState<"name", { admin: string; enabled: string }>(
    { key: "name", dir: "asc" },
    { admin: "", enabled: "" },
  );
  const all = accounts ?? [];
  const page = listPage(all, {
    filter: (a) =>
      (!list.filters.admin || String(a.is_admin) === list.filters.admin) &&
      (!list.filters.enabled || String(a.enabled) === list.filters.enabled) &&
      matchesText(list.query, a.name),
    compare: compareBy((a) => a.name),
    page: list.page,
    pageSize: PAGE_SIZE,
  });
  const admins = all.filter((a) => a.is_admin).length;

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel__toolbar">
          <h2>Sesiones activas</h2>
          <span className="muted small">{sessions.length} usuarios conectados</span>
        </div>
        {sessions.length === 0 ? (
          <EmptyState title="Nadie conectado" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>Terminal</th>
                  <th>Origen</th>
                  <th>Sesión desde</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((u, index) => (
                  <tr key={`${u.name}-${index}`}>
                    <td className="strong">{u.name}</td>
                    <td>{u.terminal ?? "—"}</td>
                    <td>{u.host ?? "local"}</td>
                    <td>{formatDateTime(u.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel__toolbar">
          <h2>Cuentas locales</h2>
          <span className="muted small">
            {all.length} cuentas · {admins} administradores
          </span>
        </div>
        {accounts === undefined ? (
          <EmptyState title="Sin cuentas">Requiere una versión reciente del agente.</EmptyState>
        ) : (
          <>
            <Toolbar>
              <SearchInput value={list.query} onChange={list.setQuery} placeholder="Buscar cuenta" label="Buscar cuentas" />
              <FilterSelect
                label="Administrador"
                value={list.filters.admin}
                options={[
                  { value: "true", label: "Sí" },
                  { value: "false", label: "No" },
                ]}
                onChange={(v) => list.setFilter("admin", v)}
              />
              <FilterSelect
                label="Estado"
                value={list.filters.enabled}
                options={[
                  { value: "true", label: "Habilitada" },
                  { value: "false", label: "Deshabilitada" },
                ]}
                onChange={(v) => list.setFilter("enabled", v)}
              />
            </Toolbar>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Cuenta</th>
                    <th>Estado</th>
                    <th>Administrador</th>
                    <th>Último inicio de sesión</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((a) => (
                    <tr key={a.name}>
                      <td className="strong">{a.name}</td>
                      <td className={a.enabled === false ? "muted" : undefined}>
                        {yesNo(a.enabled, "Habilitada", "Deshabilitada")}
                      </td>
                      <td>{a.is_admin ? <span className="badge badge--crit">Administrador</span> : yesNo(a.is_admin, "Sí", "No")}</td>
                      <td className="muted" title={formatDateTime(a.last_logon)}>
                        {a.last_logon ? formatRelative(a.last_logon) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="cuentas" />
          </>
        )}
      </section>
    </div>
  );
}
