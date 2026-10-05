import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { errorMessage } from "../lib/format";
import { useAuth } from "./AuthContext";

/**
 * Pantalla de login. La contraseña vive solo en el estado del formulario mientras se
 * escribe y se descarta tras el intento; nunca se guarda ni se registra.
 */
export function LoginPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const from = (location.state as { from?: string } | null)?.from;
  // Solo rutas internas: un `from` manipulado no puede llevar a otro sitio.
  const target = from?.startsWith("/") && !from.startsWith("//") && from !== "/login" ? from : "/";

  if (auth.status === "authenticated") return <Navigate to={target} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await auth.login(username, password);
      navigate(target, { replace: true });
    } catch (err) {
      // El backend responde lo mismo para usuario inexistente y contraseña incorrecta.
      setError(
        err instanceof ApiError && err.code === "invalid_credentials"
          ? "Usuario o contraseña incorrectos."
          : err instanceof Error
            ? errorMessage(err)
            : String(err),
      );
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="login__card panel" onSubmit={(event) => void submit(event)}>
        <div className="brand login__brand">
          <img src="/favicon.svg" alt="" width={28} height={28} />
          <span>Sentra</span>
        </div>
        <h1>Iniciar sesión</h1>
        {auth.notice && !error && (
          <div className="banner" role="status">
            {auth.notice}
          </div>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <label className="form-field">
          <span>Usuario</span>
          <input
            className="input"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            maxLength={128}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoFocus
          />
        </label>
        <label className="form-field">
          <span>Contraseña</span>
          <input
            className="input"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={256}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <button type="submit" className="button button--primary" disabled={busy || !username || !password}>
          {busy ? "Entrando…" : "Entrar"}
        </button>
        {window.location.protocol === "http:" &&
          !["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname) && (
            <p className="muted small">
              Conexión sin cifrar (HTTP): la contraseña viaja en claro por la red. Para uso real
              desde otros equipos, publica Sentra por HTTPS.
            </p>
          )}
      </form>
    </div>
  );
}
