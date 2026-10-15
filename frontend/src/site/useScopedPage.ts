import { useState } from "react";
import { useSite } from "./SiteContext";

/**
 * Página de una lista paginada en el servidor que vuelve a la primera al cambiar el alcance
 * de site (la página 3 de un site no tiene sentido en otro). Sin efectos: la página se guarda
 * junto al alcance en el que se eligió.
 */
export function useScopedPage(): [number, (page: number) => void] {
  const { scopeId } = useSite();
  const [state, setState] = useState<{ scope: string | undefined; page: number }>({ scope: scopeId, page: 1 });
  const page = state.scope === scopeId ? state.page : 1;
  return [page, (next: number) => setState({ scope: scopeId, page: next })];
}
