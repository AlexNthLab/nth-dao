/**
 * v2 entry point — `npm run dev -- --mode v2` would mount this
 * App against the same `#root` as the existing v1.
 *
 * For now, swap the import in `frontend/index.html` (or your dev
 * server's entry) from `src/main.tsx` to `src/v2/main.tsx` to
 * preview the new shell.
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
