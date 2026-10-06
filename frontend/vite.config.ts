import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// In development the browser calls the API on the same origin (/api) and Vite
// forwards it to the backend, so no CORS setup is needed for local work.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiTarget = env.SENTRA_API_PROXY_TARGET || "http://localhost:8000";

  return {
    plugins: [react()],
    build: {
      // Fase 4M: sin source maps en producción por defecto (exponen el código fuente completo
      // a cualquiera que abra el dashboard). SENTRA_BUILD_SOURCEMAP=true solo para depurar.
      sourcemap: env.SENTRA_BUILD_SOURCEMAP === "true",
    },
    server: {
      port: Number(env.SENTRA_FRONTEND_PORT) || 5173,
      strictPort: true,
      proxy: {
        // changeOrigin: false conserva el Host del navegador (p. ej. 192.168.1.10:5173): la API
        // compara el Origin de cada petición mutable con su propio origen (defensa CSRF) y
        // así funciona igual desde localhost que desde otra PC de la LAN.
        // xfwd: añade X-Forwarded-For con la IP real del navegador; la API solo la acepta
        // porque Vite corre en la misma máquina (127.0.0.1 está en TRUSTED_PROXIES), y así el
        // rate limiting del login y la auditoría ven cada PC en lugar de "127.0.0.1".
        "/api": { target: apiTarget, changeOrigin: false, xfwd: true },
      },
    },
  };
});
