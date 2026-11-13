# Python HTTP Server Test

A small Flask service intended for deployment as a public HTTP endpoint.

## Endpoints

- `GET /` - service information
- `GET /health` - health check
- `POST /echo` - echoes JSON or plain-text request data (maximum body size: 64 KiB)

## Deploy on Render

1. In Render, choose **New → Web Service** and connect this repository.
2. Set **Root Directory** to `python-server`.
3. Set **Build Command** to `pip install -r requirements.txt`.
4. Set **Start Command** to `gunicorn app:app --bind 0.0.0.0:$PORT`.
5. Choose an available instance plan and deploy.

Render will assign the service a public HTTPS hostname after a successful deployment.

## Test

Replace `YOUR-SERVICE.onrender.com` with the hostname Render assigns:

```sh
curl https://YOUR-SERVICE.onrender.com/health
curl -X POST https://YOUR-SERVICE.onrender.com/echo \
  -H 'Content-Type: application/json' \
  -d '{"hello":"world"}'
```

This is a test endpoint, not a general-purpose proxy. Do not add secrets or private data to this public repository.
