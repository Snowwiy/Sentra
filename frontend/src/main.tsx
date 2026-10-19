import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
// Orden de las hojas (Fase 6C): tokens y base, estructura, módulos y, al final, los
// componentes del design system y los ajustes responsive, que deben ganar a las reglas
// anteriores de cada módulo con la misma especificidad.
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/shell.css";
import "./index.css";
import "./styles/components.css";
import "./styles/responsive.css";

const root = document.getElementById("root");
if (!root) throw new Error("Root element #root not found");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
