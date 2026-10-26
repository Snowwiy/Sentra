import { Link } from "react-router-dom";
import { EmptyState } from "../components/StateViews";

export function NotFoundPage() {
  return (
    <div className="page">
      <EmptyState title="Página no encontrada">
        <Link to="/">Volver al panel</Link>
      </EmptyState>
    </div>
  );
}
