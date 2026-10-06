import { useEffect, useState } from "react";
import { sentraApi } from "../api/sentra";
import { useDebounced } from "./useDebounced";

/** Opciones mostradas como máximo en un selector de activo. */
export const ASSET_OPTIONS_LIMIT = 50;

export interface AssetOption {
  asset_id: string;
  display_name: string;
  primary_ip: string | null;
}

/**
 * Opciones para un selector de activo (Fase 4M). Antes se descargaba el inventario completo
 * para rellenar un <select>; con miles de activos eso es lento y pesado. Ahora se piden al
 * servidor los primeros ASSET_OPTIONS_LIMIT por nombre que coinciden con la búsqueda, y el
 * activo ya elegido se mantiene en la lista aunque no esté entre ellos.
 */
export function useAssetOptions(query: string, selectedId = ""): AssetOption[] {
  const q = useDebounced(query.trim(), 300);
  const [found, setFound] = useState<AssetOption[]>([]);
  const [selected, setSelected] = useState<AssetOption>();

  useEffect(() => {
    const controller = new AbortController();
    sentraApi
      .listAssets(controller.signal, { q: q || undefined, sort: "name", limit: ASSET_OPTIONS_LIMIT })
      .then((list) => setFound(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, [q]);

  const missing = selectedId !== "" && !found.some((a) => a.asset_id === selectedId);
  useEffect(() => {
    if (!missing || selected?.asset_id === selectedId) return;
    const controller = new AbortController();
    sentraApi
      .getAsset(selectedId, controller.signal)
      .then((asset) => setSelected(asset))
      .catch(() => undefined);
    return () => controller.abort();
  }, [missing, selectedId, selected]);

  if (missing && selected?.asset_id === selectedId) return [selected, ...found];
  return found;
}
