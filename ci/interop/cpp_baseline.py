"""Pinned active C++ reference and explicit historical replay selection."""

PREVIOUS_CPP_REVISION = "881240331ee48a291b96d73f8b8b93bae005ace0"
ACTIVE_CPP_REVISION = "ed8e0a80bdafede324d97b041fa4174e0a5dce33"
PREVIOUS_ACTIVE_CPP_REVISION = "5af405dcb1f523be0ff3b812e9f6945275c4945b"
HISTORICAL_CPP_REVISIONS = frozenset(
    {
        PREVIOUS_CPP_REVISION,
        PREVIOUS_ACTIVE_CPP_REVISION,
        "8f083dc06bff16705710a01de15eb3123d5d696b",
    }
)
DEFAULT_AUTH_NETWORK_TAG = (
    "76b12fa4e8d1d6b2f8738db6350c388dd28ac69fbb8458199e08a928cfc8f96a"
)


def require_cpp_baseline(revision, profile=None):
    expected = ACTIVE_CPP_REVISION if profile is None else profile["cpp_revision"]
    if revision != expected or expected not in HISTORICAL_CPP_REVISIONS | {
        ACTIVE_CPP_REVISION,
    }:
        raise ValueError("C++ snapshot must match the explicitly pinned baseline")


def configure_auth_namespace(config, profile):
    if profile["cpp_revision"] not in {
        ACTIVE_CPP_REVISION,
        PREVIOUS_CPP_REVISION,
        PREVIOUS_ACTIVE_CPP_REVISION,
    }:
        return
    tag = profile.get("auth_network_tag")
    if (
        not isinstance(tag, str)
        or len(tag) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in tag)
    ):
        raise ValueError(
            "Current C++ baseline requires an explicit 32-byte AUTH network tag"
        )
    config.auth_network_tag = bytes.fromhex(tag)
