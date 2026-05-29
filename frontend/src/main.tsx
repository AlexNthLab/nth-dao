import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./AppShell";
import Overview from "./pages/Overview";
import Agents from "./pages/Agents";
import Kanban from "./pages/Kanban";
import Missions from "./pages/Missions";
import ChatRoom from "./pages/ChatRoom";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview />} />
          <Route path="agents" element={<Agents />} />
          <Route path="kanban" element={<Kanban />} />
          <Route path="missions" element={<Missions />} />
          <Route path="chat" element={<ChatRoom />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
