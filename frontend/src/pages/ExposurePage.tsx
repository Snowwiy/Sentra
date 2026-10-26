import { Link, useSearchParams } from "react-router-dom";
import { ExposureList } from "../components/vulnerabilities/ExposureList";

/**
 * Exposición consolidada (Fase 5B): puertos observados por Discovery, contexto declarado del
 * activo y vulnerabilidades del servicio. Un puerto abierto no es una vulnerabilidad: aquí
 * solo se muestra lo observado, con etiquetas que dicen desde dónde.
 */
export function ExposurePage() {
  const [params] = useSearchParams();
  const assetId = params.get("asset") ?? undefined;
  return (
    <div className="page">
      <Link to="/vulnerabilities" className="muted">
        ← Vulnerabilidades
      </Link>
      <div className="page__header">
        <div>
          <h1>Exposición</h1>
          <p className="muted small">
            Servicios observados desde el sensor de Sentra (LAN). Sentra no escanea desde Internet: "expuesto a Internet"
            solo aparece si el contexto del activo lo declara.
          </p>
        </div>
      </div>
      {assetId && (
        <div className="banner" role="note">
          Filtrado por un activo. <Link to="/vulnerabilities/exposure">Ver todos</Link>
        </div>
      )}
      <ExposureList assetId={assetId} />
    </div>
  );
}
