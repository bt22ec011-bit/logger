import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      // Proxy is OPTIONAL. When you run the logging agent in proxy mode,
      // set VITE_PROXY_TARGET to the agent's proxy port (e.g. 4100) so
      // API calls are observed exactly once by the agent.
      proxy: env.VITE_PROXY_TARGET
        ? { '/api': { target: env.VITE_PROXY_TARGET, changeOrigin: false } }
        : undefined,
    },
  };
});
