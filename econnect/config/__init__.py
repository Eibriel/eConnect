try:
    from econnect.config.local import Local as Config
except:
    raise
    print("Loading default Config")
    from econnect.config.default import Config
