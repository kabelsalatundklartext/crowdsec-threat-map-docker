worker_processes 1;
error_log /dev/stderr warn;
pid /run/nginx/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    access_log    /dev/stdout;
    sendfile      on;
    keepalive_timeout 65;

    server {
        listen 8080;
        server_name _;
        root /var/www/html;
        index index.html;

        # Dashboard
        location / {
            try_files $uri $uri/ /index.html;
        }

        # Exporter-API Endpunkte — Proxy zu Python (Port 9456)
        location /metrics {
            proxy_pass http://127.0.0.1:9456/metrics;
            proxy_set_header Host $host;
            add_header Access-Control-Allow-Origin *;
        }

        location /unban {
            proxy_pass http://127.0.0.1:9456/unban;
            proxy_set_header Host $host;
            add_header Access-Control-Allow-Origin *;
        }

        location /decisions {
            proxy_pass http://127.0.0.1:9456/decisions;
            proxy_set_header Host $host;
            add_header Access-Control-Allow-Origin *;
        }

        location /whitelist-status {
            proxy_pass http://127.0.0.1:9456/whitelist-status;
            proxy_set_header Host $host;
            add_header Access-Control-Allow-Origin *;
        }
    }
}
