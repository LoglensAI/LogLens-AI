"""Confirm every fix is present and consistent. Run after copying files:
    python verify_install.py
"""
import importlib, sys
ok = True
def chk(mod, attr):
    global ok
    try:
        m = importlib.import_module(mod)
        present = hasattr(m, attr)
    except Exception as e:
        present = False; m = None
    tag = "OK " if present else "MISSING"
    if not present: ok = False
    print(f"  [{tag}] {mod}.{attr}" + (f"   <- {m.__file__}" if m is not None and not present else ""))
chk("loglens.application.api", "apply_supervised_head")
chk("loglens.application.autoscale", "mem_capped_workers")
chk("loglens.application.daemon", "local_ipc_viable")
chk("loglens.detection.synonyms", "_MAX_SYNONYM_VOCAB")
chk("loglens.detection.detector", "MAX_CLUSTER_GROUPS")
try:
    import loglens.domain.errors  # noqa
    print("  [OK ] loglens.domain.errors module")
except Exception:
    ok = False; print("  [MISSING] loglens.domain.errors module")
# the critical cross-file import the workers do:
try:
    from loglens.application.parallel_scan import _analyze_slice  # noqa
    from loglens.application.api import apply_supervised_head  # noqa
    print("  [OK ] worker import chain (parallel_scan -> api.apply_supervised_head)")
except Exception as e:
    ok = False; print(f"  [MISSING] worker import chain: {e}")
print("\nRESULT:", "ALL GOOD — safe to run analyze" if ok else "INCOMPLETE — copy the missing file(s) and reinstall")
sys.exit(0 if ok else 1)
