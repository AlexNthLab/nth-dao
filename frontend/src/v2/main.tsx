/**
 * v2 entry point.
 *
 * Preview path: ``http://127.0.0.1:5173/v2.html`` (served by
 * Vite when ``npm run dev`` is running from ``frontend/``).
 * The companion ``v2.html`` next to ``index.html`` is what loads
 * this module — no swap of the v1 entry needed.
 *
 * v1 keeps its own ``index.html`` → ``src/main.tsx``, so both
 * UIs co-exist during the migration. Once v2 reaches feature
 * parity, ``index.html`` flips to point here and the v1 source
 * goes to ``src/v1-legacy/`` for archival.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
