"""Compatibility shim for the historical gateway module path.

The production HTTP gateway now lives in ``agentvault_gateway.app``. Keep this
module so older dev commands and imports fail less abruptly while docs/tests
move to the new package.
"""

from agentvault_gateway.app import *  # noqa: F401,F403

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("agentvault_gateway.app:app", host="0.0.0.0", port=8000, reload=False)
