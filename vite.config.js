import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'dynamic-elastic-proxy',
      configureServer(server) {
        server.middlewares.use('/elastic_api', async (req, res, next) => {
          const targetUrl = req.headers['x-target-url'];
          if (!targetUrl) {
             res.statusCode = 400;
             return res.end('Missing x-target-url header');
          }

          let bodyData = null;
          if (req.method !== 'GET' && req.method !== 'HEAD') {
            bodyData = await new Promise((resolve) => {
              let body = '';
              req.on('data', chunk => body += chunk.toString());
              req.on('end', () => resolve(body));
            });
          }

          // Construct the final URL
          const fetchUrl = targetUrl + req.originalUrl.replace('/elastic_api', '');
          
          try {
            const fetchRes = await fetch(fetchUrl, {
              method: req.method,
              headers: {
                'Content-Type': req.headers['content-type'] || 'application/json',
                'Authorization': req.headers['authorization']
              },
              body: bodyData
            });
            
            const data = await fetchRes.text();
            res.statusCode = fetchRes.status;
            res.setHeader('Content-Type', fetchRes.headers.get('content-type') || 'application/json');
            res.end(data);
          } catch (e) {
            res.statusCode = 502;
            res.end("Bad Gateway: " + e.message);
          }
        });
      }
    }
  ]
})
