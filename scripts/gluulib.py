import json
import logging
import os

import six
# import kubernetes.client
# import kubernetes.config
from consul import Consul

import hvac

logger = logging.getLogger("gluu_config")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

# # the namespace used for storing configmap
# GLUU_KUBERNETES_NAMESPACE = os.environ.get("GLUU_KUBERNETES_NAMESPACE",
#                                            "default")
# # the name of the configmap
# GLUU_KUBERNETES_CONFIGMAP = os.environ.get("GLUU_KUBERNETES_CONFIGMAP", "gluu")


def as_boolean(val, default=False):
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


class BaseConfig(object):
    """Base class for config adapter. Must be sub-classed per
    implementation details.
    """

    def get(self, key, default=None):
        """Get specific config.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def set(self, key, value):
        """Set specific config.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def all(self):
        """Get all config as ``dict`` type.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def _prepare_value(self, value):
        if not isinstance(value, (six.string_types, six.binary_type)):
            value = json.dumps(value)
        return value


class ConsulConfig(BaseConfig):
    def __init__(self):
        # collects all env vars prefixed with `GLUU_CONFIG_CONSUL_`,
        # for example `GLUU_CONFIG_CONSUL_HOST=localhost`
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_CONFIG_CONSUL_")
        }

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_HOST",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_HOST", "localhost"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_PORT",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_PORT", 8500),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CONSISTENCY",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CONSISTENCY", "stale"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_SCHEME",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_SCHEME", "http"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_VERIFY",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_VERIFY", False),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CACERT_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CACERT_FILE",
                           "/etc/certs/consul_ca.crt"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CERT_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CERT_FILE",
                           "/etc/certs/consul_client.crt"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_KEY_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_KEY_FILE",
                           "/etc/certs/consul_client.key"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_TOKEN_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_TOKEN_FILE", "/etc/certs/consul_token"),
        )

        self.prefix = "gluu/config/"
        token = None
        cert = None
        verify = False

        if os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_TOKEN_FILE"]):
            with open(self.settings["GLUU_CONFIG_CONSUL_TOKEN_FILE"]) as fr:
                token = fr.read().strip()

        if self.settings["GLUU_CONFIG_CONSUL_SCHEME"] == "https":
            verify = as_boolean(self.settings["GLUU_CONFIG_CONSUL_VERIFY"])

            # verify using CA cert (if any)
            if all([verify,
                    os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_CACERT_FILE"])]):
                verify = self.settings["GLUU_CONFIG_CONSUL_CACERT_FILE"]

            if all([os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_CERT_FILE"]),
                    os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_KEY_FILE"])]):
                cert = (self.settings["GLUU_CONFIG_CONSUL_CERT_FILE"],
                        self.settings["GLUU_CONFIG_CONSUL_KEY_FILE"])

        self._request_warning(self.settings["GLUU_CONFIG_CONSUL_SCHEME"], verify)

        self.client = Consul(
            host=self.settings["GLUU_CONFIG_CONSUL_HOST"],
            port=self.settings["GLUU_CONFIG_CONSUL_PORT"],
            token=token,
            scheme=self.settings["GLUU_CONFIG_CONSUL_SCHEME"],
            consistency=self.settings["GLUU_CONFIG_CONSUL_CONSISTENCY"],
            verify=verify,
            cert=cert,
        )

    def _merge_path(self, key):
        """Add prefix to the key.
        """
        return "".join([self.prefix, key])

    def _unmerge_path(self, key):
        """Remove prefix from the key.
        """
        return key[len(self.prefix):]

    def get(self, key, default=None):
        _, result = self.client.kv.get(self._merge_path(key))
        if not result:
            return default
        return result["Value"]

    def set(self, key, value):
        return self.client.kv.put(self._merge_path(key),
                                  self._prepare_value(value))

    def find(self, key):
        _, resultset = self.client.kv.get(self._merge_path(key),
                                          recurse=True)

        if not resultset:
            return {}

        return {
            self._unmerge_path(item["Key"]): item["Value"]
            for item in resultset
        }

    def all(self):
        return self.find("")

    def _request_warning(self, scheme, verify):
        if scheme == "https" and verify is False:
            import urllib3
            urllib3.disable_warnings()
            logger.warn(
                "All requests to Consul will be unverified. "
                "Please adjust GLUU_CONFIG_CONSUL_SCHEME and "
                "GLUU_CONFIG_CONSUL_VERIFY environment variables."
            )


# class KubernetesConfig(BaseConfig):
#     def __init__(self):
#         kubernetes.config.load_incluster_config()
#         self.client = kubernetes.client.CoreV1Api()
#         self.name_exists = False

#     def get(self, key, default=None):
#         result = self.all()
#         return result.get(key, default)

#     def _prepare_configmap(self):
#         # create a configmap name if not exist
#         if not self.name_exists:
#             try:
#                 self.client.read_namespaced_config_map(
#                     GLUU_KUBERNETES_CONFIGMAP,
#                     GLUU_KUBERNETES_NAMESPACE)
#                 self.name_exists = True
#             except kubernetes.client.rest.ApiException as exc:
#                 if exc.status == 404:
#                     # create the configmaps name
#                     body = {
#                         "kind": "ConfigMap",
#                         "apiVersion": "v1",
#                         "metadata": {
#                             "name": GLUU_KUBERNETES_CONFIGMAP,
#                         },
#                         "data": {},
#                     }
#                     created = self.client.create_namespaced_config_map(
#                         GLUU_KUBERNETES_NAMESPACE,
#                         body)
#                     if created:
#                         self.name_exists = True
#                 else:
#                     raise

#     def set(self, key, value):
#         self._prepare_configmap()
#         body = {
#             "kind": "ConfigMap",
#             "apiVersion": "v1",
#             "metadata": {
#                 "name": GLUU_KUBERNETES_CONFIGMAP,
#             },
#             "data": {
#                 key: self._prepare_value(value),
#             }
#         }
#         return self.client.patch_namespaced_config_map(
#             GLUU_KUBERNETES_CONFIGMAP,
#             GLUU_KUBERNETES_NAMESPACE,
#             body=body)

#     def all(self):
#         self._prepare_configmap()
#         result = self.client.read_namespaced_config_map(
#             GLUU_KUBERNETES_CONFIGMAP,
#             GLUU_KUBERNETES_NAMESPACE)
#         return result.data or {}


class ConfigManager(object):
    settings = {}

    def __init__(self):
        self.settings["GLUU_CONFIG_ADAPTER"] = os.environ.get(
            "GLUU_CONFIG_ADAPTER",
            "consul",
        )
        if self.settings["GLUU_CONFIG_ADAPTER"] == "consul":
            self.adapter = ConsulConfig()
        # elif self.settings["GLUU_CONFIG_ADAPTER"] == "kubernetes":
        #     self.adapter = KubernetesConfig()
        else:
            self.adapter = None

    def get(self, key, default=None):
        return self.adapter.get(key, default)

    def set(self, key, value):
        return self.adapter.set(key, value)

    def all(self):
        return self.adapter.all()


class BaseSecret(object):
    """Base class for secret adapter. Must be sub-classed per
    implementation details.
    """

    def get(self, key, default=None):
        """Get specific secret.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def set(self, key, value):
        """Set specific secret.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def all(self):
        """Get all secrets as ``dict`` type.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError


class VaultSecret(BaseSecret):
    def __init__(self):
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_SECRET_VAULT_")
        }
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_URL",
            "http://localhost:8200",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_ROLE_ID_FILE",
            "/run/secrets/vault_role_id",
        ),
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_ROLE_ID_FILE",
            "/run/secrets/vault_secret_id",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_CERT_FILE",
            "/etc/certs/vault_client.crt",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_KEY_FILE",
            "/etc/certs/vault_client.key",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_CACERT_FILE",
            "/etc/certs/vault_ca.crt",
        )

        cert = None
        verify = self.settings["GLUU_SECRET_VAULT_URL"].startswith("https")

        # verify using CA cert (if any)
        if verify and os.path.isfile(self.settings["GLUU_SECRET_VAULT_CACERT_FILE"]):
            verify = self.settings["GLUU_SECRET_VAULT_CACERT_FILE"]

        if all([os.path.isfile(self.settings["GLUU_SECRET_VAULT_CERT_FILE"]),
                os.path.isfile(self.settings["GLUU_SECRET_VAULT_KEY_FILE"])]):
            cert = (self.settings["GLUU_SECRET_VAULT_CERT_FILE"],
                    self.settings["GLUU_SECRET_VAULT_KEY_FILE"])

        self.client = hvac.Client(
            url=self.settings["GLUU_SECRET_VAULT_URL"],
            cert=cert,
            verify=verify,
        )
        self.prefix = "secret/gluu"

    @property
    def role_id(self):
        try:
            with open(self.settings["GLUU_SECRET_VAULT_ROLE_ID_FILE"]) as f:
                role_id = f.read()
        except IOError:
            role_id = ""
        return role_id

    @property
    def secret_id(self):
        try:
            with open(self.settings["GLUU_SECRET_VAULT_SECRET_ID_FILE"]) as f:
                secret_id = f.read()
        except IOError:
            secret_id = ""
        return secret_id

    def _authenticate(self):
        if self.client.is_authenticated():
            return

        try:
            self.client.auth_approle(self.role_id, self.secret_id)
        except (hvac.exceptions.InvalidRequest,
                hvac.exceptions.VaultDown) as exc:
            raise RuntimeError("Unable to authenticate; "
                               "reason={}".format(exc))

    def get(self, key, default=None):
        self._authenticate()
        sc = self.client.read("{}/{}".format(self.prefix, key))
        if not sc:
            return default
        return sc["data"]["value"]

    def set(self, key, value):
        self._authenticate()
        val = {"value": value}
        self.client.write("{}/{}".format(self.prefix, key), **val)


class SecretManager(object):
    settings = {}

    def __init__(self):
        self.settings["GLUU_SECRET_ADAPTER"] = os.environ.get(
            "GLUU_SECRET_ADAPTER",
            "vault",
        )
        if self.settings["GLUU_SECRET_ADAPTER"] == "vault":
            self.adapter = VaultSecret()
        else:
            self.adapter = None

    def get(self, key, default=None):
        return self.adapter.get(key, default)

    def set(self, key, value):
        return self.adapter.set(key, value)

    def all(self):
        return self.adapter.all()
