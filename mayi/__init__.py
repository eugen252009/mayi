"""Semantic operation model for the mayi privilege broker."""

def __getattr__(name):
    if name == "__version__":
        from .version import get_version
        return get_version()
    raise AttributeError(name)
