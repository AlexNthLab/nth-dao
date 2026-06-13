import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// 多入口构建（2026-06-13 修复）：仓库有两个前端入口 ——
//   index.html → src/main.tsx       （v1 控制台）
//   v2.html    → src/v2/main.tsx     （v2 控制台，agents / 任务流式输出在这）
// 之前 vite.config 没配 rollupOptions.input，``vite build`` 只构建
// index.html(v1)，而 ``emptyOutDir:true`` 还会把已有的 v2 资源清掉 ——
// 于是 hub 服务的 v2 控制台要么缺失要么陈旧，UI 看不到 agents/任务流。
// 这里显式把两个入口都列进 input，一次 build 同时产出 v1 + v2 静态资源。
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../nth_dao/web/static",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
        v2: fileURLToPath(new URL("v2.html", import.meta.url)),
      },
    },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080"
    }
  }
});
