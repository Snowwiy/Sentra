import { Link } from "react-router-dom";
import { ExposureList } from "../../components/vulnerabilities/ExposureList";

/**
 * Red › Puertos y servicios (Fase 7A.5): los servicios abiertos de todos los dispositivos, con
 * su servicio probable, si son sensibles o nuevos, el proceso que escucha (con agente) y sus
 * vulnerabilidades. Es la misma exposición consolidada de Vulnerabilidades (vulnerabilities:read).
 */
export function ServicesTab() {
  return (
    <div className="stack">
      <p className="muted small">
        Puertos observados desde Sentra en la red local y escuchas informadas por los agentes. Un puerto abierto no es
        una vulnerabilidad; «expuesto a Internet» solo aparece si el contexto del activo lo declara. Para los puertos de
        un equipo concreto, abre su ficha desde <Link to="/network/devices">Dispositivos</Link>.
      </p>
      <ExposureList />
    </div>
  );
}
