"""Business services — logic shared by routers, workers and schedulers.

The rule this package exists to enforce: **routers stay thin, and nothing
imports from `envelock.api.*` except the app wiring in `main.py`.** Before it
existed, the scheduler imported domain re-verification from a FastAPI router
module and one router reached into another router's private helpers — the
import graph made every route module load-bearing for background jobs.

When a helper in an `api/` module turns out to be needed anywhere else, it
moves here first.
"""
