import logging, time
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.logging_config import configure_logging
from app.vvp.api_models import VerifyRequest
from app.vvp.verify import verify_vvp

configure_logging()
log = logging.getLogger("vvp")

app = FastAPI(title="VVP Verifier", version="0.1.0")
app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/")
def index():
    return FileResponse("web/index.html")

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.middleware("http")
async def req_log(request: Request, call_next):
    start = time.time()
    route = request.url.path
    remote = request.client.host if request.client else "-"
    resp = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)
    log.info(f"request_complete status={resp.status_code} duration_ms={duration_ms}",
             extra={"request_id":"-", "route":route, "remote_addr":remote})
    return resp

@app.post("/verify")
async def verify(req: VerifyRequest, request: Request):
    req_id, resp = verify_vvp(req)
    log.info("verify_called", extra={"request_id":req_id, "route":"/verify",
                                    "remote_addr": request.client.host if request.client else "-"})
    return JSONResponse(resp.model_dump())
