"""Supply the explicit AUTH namespace to the pinned native diagnostic helper."""

from cpp_baseline import configure_auth_namespace, require_cpp_baseline


def network_factory(network_type, profile):
    require_cpp_baseline(profile["cpp_revision"], profile)

    def create(*args, **kwargs):
        network = network_type(*args, **kwargs)
        configure_auth_namespace(network.config, profile)
        return network

    return create
