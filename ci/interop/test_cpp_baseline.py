import types
import unittest

from cpp_baseline import (
    ACTIVE_CPP_REVISION,
    HISTORICAL_CPP_REVISIONS,
    configure_auth_namespace,
    require_cpp_baseline,
)


class CppBaselineTests(unittest.TestCase):
    def test_active_default_rejects_old_and_unknown_snapshots(self):
        require_cpp_baseline(ACTIVE_CPP_REVISION)
        for revision in [next(iter(HISTORICAL_CPP_REVISIONS)), "0" * 40]:
            with self.assertRaises(ValueError):
                require_cpp_baseline(revision)

    def test_historical_replay_requires_matching_explicit_profile(self):
        old = next(iter(HISTORICAL_CPP_REVISIONS))
        require_cpp_baseline(old, {"cpp_revision": old})
        with self.assertRaises(ValueError):
            require_cpp_baseline(ACTIVE_CPP_REVISION, {"cpp_revision": old})
        with self.assertRaises(ValueError):
            require_cpp_baseline("0" * 40, {"cpp_revision": "0" * 40})

    def test_current_genesis_refuses_missing_or_malformed_namespace(self):
        for tag in [None, "", "a" * 63, "z" * 64, 42]:
            config = types.SimpleNamespace(auth_network_tag=None)
            with self.assertRaises(ValueError):
                configure_auth_namespace(
                    config,
                    {"cpp_revision": ACTIVE_CPP_REVISION, "auth_network_tag": tag},
                )
            self.assertIsNone(config.auth_network_tag)
        config = types.SimpleNamespace()
        configure_auth_namespace(
            config, {"cpp_revision": ACTIVE_CPP_REVISION, "auth_network_tag": "AB" * 32}
        )
        self.assertEqual(config.auth_network_tag, bytes.fromhex("ab" * 32))

    def test_historical_genesis_needs_no_new_namespace(self):
        config = types.SimpleNamespace()
        configure_auth_namespace(
            config, {"cpp_revision": next(iter(HISTORICAL_CPP_REVISIONS))}
        )
        self.assertFalse(hasattr(config, "auth_network_tag"))


if __name__ == "__main__":
    unittest.main()
