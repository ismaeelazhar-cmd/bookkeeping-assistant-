import multiprocessing

# Bind to localhost only — this app has no built-in HTTPS. Put a reverse proxy
# (nginx/Caddy) in front to terminate TLS and forward to this port. See README.md.
bind = "127.0.0.1:5050"

# SQLite tolerates a handful of concurrent writers but isn't built for heavy write
# concurrency. A small worker count is the right call for this app's actual load —
# more workers won't help once SQLite's single-writer lock is the bottleneck.
workers = min(4, multiprocessing.cpu_count())
threads = 2
worker_class = "gthread"

timeout = 60
graceful_timeout = 30
accesslog = "-"
errorlog = "-"
