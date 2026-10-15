import { Link } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { reportHref, type PrefillParam } from "../../lib/reportLinks";

/**
 * Enlace "Generar informe" a /reports con el formulario precargado. Solo con reports:generate;
 * la página y la API vuelven a comprobar el permiso igualmente.
 */
export function GenerateReportLink({
  type,
  ids = {},
  label = "Generar informe",
}: {
  type: string;
  ids?: Partial<Record<PrefillParam, string>>;
  label?: string;
}) {
  const auth = useAuth();
  if (!auth.can("reports:generate")) return null;
  return (
    <Link className="button button--small" to={reportHref(type, ids)}>
      {label}
    </Link>
  );
}
