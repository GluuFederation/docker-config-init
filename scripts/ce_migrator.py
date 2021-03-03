# import contextlib
import json
import logging.config
import os
import time
import uuid

import javaproperties
from ldif3 import LDIFParser

from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import get_random_chars
from pygluu.containerlib.utils import generate_ssl_certkey
from pygluu.containerlib.utils import exec_cmd

from settings import LOGGING_CONFIG

DEFAULT_SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512"
DEFAULT_ENC_KEYS = DEFAULT_SIG_KEYS

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("config-init")


def generate_openid_keys(passwd, jks_path, jwks_path, dn, exp=365, sig_keys="", enc_keys=""):
    sig_keys = sig_keys or DEFAULT_SIG_KEYS
    enc_keys = enc_keys or DEFAULT_ENC_KEYS

    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-jar", "/app/javalibs/oxauth-client.jar",
        "-enc_keys", enc_keys,
        "-sig_keys", sig_keys,
        "-dnname", "{!r}".format(dn),
        "-expiration", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])
    try:
        os.unlink(jks_path)
    except OSError:
        pass
    out, err, retcode = exec_cmd(cmd)

    if retcode == 0:
        with open(jwks_path, "w") as f:
            f.write(out.decode())
    return out, err, retcode


def export_openid_keys(keystore, keypasswd, alias, export_file):
    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-cp /app/javalibs/oxauth-client.jar",
        "org.gluu.oxauth.util.KeyExporter",
        f"-keystore {keystore}",
        f"-keypasswd {keypasswd}",
        f"-alias {alias}",
        f"-exportfile {export_file}",
    ])
    return exec_cmd(cmd)


def gen_idp3_key(storepass, sealer_jks_fn, sealer_kver_fn):
    cmd = " ".join([
        "java",
        "-classpath '/app/javalibs/*'",
        "net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategyTool",
        f"--storefile {sealer_jks_fn}",
        f"--versionfile {sealer_kver_fn}",
        "--alias secret",
        f"--storepass {storepass}",
    ])
    return exec_cmd(cmd)


def generate_pkcs12(cert_file, key_file, pkcs12_file, passwd, hostname):
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        f"-inkey {key_file}",
        f"-in {cert_file}",
        f"-out {pkcs12_file}",
        f"-name {hostname}",
        f"-passout pass:{passwd}",
    ])
    return exec_cmd(cmd)


class LdifBackend:
    def __init__(self, source_file):
        self.source_file = source_file

    def get_oxauth_jwks(self) -> str:
        jwks = ""
        with open(self.source_file, "rb") as fd:
            # with contextlib.ExitStack() as stack:
            # fd = stack.enter_context(open(self.source_file, "rb"))
            parser = LDIFParser(fd)

            for dn, entry in parser.parse():
                if dn != "ou=oxauth,ou=configuration,o=gluu":
                    continue
                jwks = entry["oxAuthConfWebKeys"][0]
        return jwks

    def get_client_jwks(self, id_) -> str:
        jwks = ""
        with open(self.source_file, "rb") as fd:
            # with contextlib.ExitStack() as stack:
            # fd = stack.enter_context(open(self.source_file, "rb"))
            parser = LDIFParser(fd)

            for dn, entry in parser.parse():
                if dn != f"inum={id_},ou=clients,o=gluu":
                    continue
                jwks = entry["oxAuthJwks"][0]
        return jwks

    def get_cache_config(self) -> dict:
        config = {}

        with open(self.source_file, "rb") as fd:
            # with contextlib.ExitStack() as stack:
            # fd = stack.enter_context(open(self.source_file, "rb"))
            parser = LDIFParser(fd)

            for dn, entry in parser.parse():
                if dn != "ou=configuration,o=gluu":
                    continue
                config = json.loads(entry["oxCacheConfiguration"][0])
        return config


class JsonBackend:
    def __init__(self, source_file):
        self.source_file = source_file
        self.bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

    def get_oxauth_jwks(self) -> str:
        jwks = ""

        with open(self.source_file) as f:
            data = json.load(f)

            for item in data:
                if item["dn"] != f"ou=oxauth,ou=configuration,o={self.bucket_prefix}":
                    continue
                jwks = json.dumps(item["oxAuthConfWebKeys"])
        return jwks

    def get_client_jwks(self, id_) -> str:
        jwks = ""
        with open(self.source_file) as f:
            data = json.load(f)

            for item in data:
                if item["dn"] != f"inum={id_},ou=clients,o={self.bucket_prefix}":
                    continue
                jwks = json.dumps(item["oxAuthJwks"])
        return jwks

    def get_cache_config(self) -> dict:
        config = {}
        with open(self.source_file) as f:
            data = json.load(f)

            for item in data:
                if item["dn"] != f"ou=configuration,o={self.bucket_prefix}":
                    continue
                config = item["oxCacheConfiguration"]
        return config


class CtxMigrator:
    def __init__(self, migration_dir="/ce", backend="ldif"):
        self.migration_dir = migration_dir

        if backend == "ldif":
            self.backend = LdifBackend(
                os.path.join(self.migration_dir, "source.ldif"),
            )
        else:
            self.backend = JsonBackend(
                os.path.join(self.migration_dir, "source.json"),
            )

        with open(os.path.join(self.migration_dir, "setup.properties")) as f:
            self.setup_props = javaproperties.load(f.read())

        self.config = {}
        self.secret = {}

    def get_redis_password(self):
        cache_conf = self.backend.get_cache_config()
        redis_conf = cache_conf["redisConfiguration"]

        if "decryptedPassword" in redis_conf:
            return redis_conf["decryptedPassword"]

        if redis_conf["password"]:
            return decode_text(redis_conf["password"], self.secret["encoded_salt"]).decode()
        return redis_conf["password"] or ""

    def get_salt(self):
        with open(os.path.join(self.migration_dir, "salt")) as f:
            txt = f.read()
            return txt.split("=")[-1].strip()

    def encode_from_file(self, fn, mode="r"):
        with open(os.path.join(self.migration_dir, fn), mode) as f:
            return encode_text(
                f.read(),
                self.secret["encoded_salt"],
            ).decode()

    def from_file(self, fn):
        with open(os.path.join(self.migration_dir, fn)) as f:
            return f.read().strip()

    def base_ctx(self):
        self.config["orgName"] = self.setup_props["orgName"]
        self.config["state"] = self.setup_props["state"]
        self.config["city"] = self.setup_props["city"]
        self.config["hostname"] = self.setup_props["hostname"]
        self.config["admin_email"] = self.setup_props["admin_email"]
        self.config["default_openid_jks_dn_name"] = self.setup_props["default_openid_jks_dn_name"]
        self.config["jetty_base"] = self.setup_props["jetty_base"]
        self.config["fido2ConfigFolder"] = self.setup_props["fido2ConfigFolder"]
        self.config["admin_inum"] = self.setup_props["admin_inum"]
        self.config["country_code"] = self.setup_props["countryCode"]
        self.secret["pairwiseCalculationKey"] = self.setup_props["pairwiseCalculationKey"]
        self.secret["pairwiseCalculationSalt"] = self.setup_props["pairwiseCalculationSalt"]
        self.secret["encoded_oxtrust_admin_password"] = self.setup_props["encoded_oxtrust_admin_password"]
        self.secret["encoded_salt"] = self.get_salt()

    def ldap_ctx(self):
        self.config["ldap_port"] = self.setup_props["ldap_port"]
        self.config["ldaps_port"] = self.setup_props["ldaps_port"]
        self.config["ldap_binddn"] = self.setup_props["ldap_binddn"]
        self.config["ldap_site_binddn"] = self.config["ldap_binddn"]
        self.config["ldap_init_host"] = "localhost"
        self.config["ldap_init_port"] = "1636"
        self.config["ldapTrustStoreFn"] = self.setup_props["ldapTrustStoreFn"]
        self.secret["encoded_ox_ldap_pw"] = self.setup_props["encoded_ox_ldap_pw"]
        self.secret["encoded_ldapTrustStorePass"] = self.setup_props["encoded_ldapTrustStorePass"]
        self.secret["ldap_truststore_pass"] = decode_text(
            self.secret["encoded_ldapTrustStorePass"],
            self.secret["encoded_salt"],
        ).decode()

        # if using Couchbase, CE won't have ``opendj.crt`` file
        if not os.path.isfile(os.path.join(self.migration_dir, "opendj.crt")):
            generate_ssl_certkey(
                "opendj",
                self.config["admin_email"],
                self.config["hostname"],
                self.config["orgName"],
                self.config["country_code"],
                self.config["state"],
                self.config["city"],
                base_dir=self.migration_dir,
                extra_dns=["ldap"],
            )

            with open(os.path.join(self.migration_dir, "opendj.pem"), "w") as fw:
                with open(os.path.join(self.migration_dir, "opendj.crt")) as fr:
                    cert = fr.read()

                with open(os.path.join(self.migration_dir, "opendj.key")) as fr:
                    key = fr.read()

                cacert = "".join([cert, key])
                fw.write(cacert)

            # generate opendj.pkcs12
            _, err, retcode = generate_pkcs12(
                os.path.join(self.migration_dir, "opendj.crt"),
                os.path.join(self.migration_dir, "opendj.key"),
                os.path.join(self.migration_dir, "opendj.pkcs12"),
                self.secret["ldap_truststore_pass"],
                self.config["hostname"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate PKCS12 file, reason={err.decode()}")

        self.secret["ldap_ssl_cert"] = self.encode_from_file("opendj.crt")

        if os.path.isfile(os.path.join(self.migration_dir, "opendj.key")):
            self.secret["ldap_ssl_key"] = self.encode_from_file("opendj.key")
        else:
            self.secret["ldap_ssl_key"] = encode_text("", self.secret["encoded_salt"]).decode()

        if os.path.isfile(os.path.join(self.migration_dir, "opendj.pem")):
            self.secret["ldap_ssl_cacert"] = self.encode_from_file("opendj.pem")
        else:
            self.secret["ldap_ssl_cacert"] = encode_text("", self.secret["encoded_salt"]).decode()
        self.secret["ldap_pkcs12_base64"] = self.encode_from_file("opendj.pkcs12", mode="rb")

    def oxauth_ctx(self):
        self.config["oxauth_client_id"] = self.setup_props["oxauth_client_id"]
        self.config["oxauth_openid_jks_fn"] = self.setup_props["oxauth_openid_jks_fn"]
        self.config["oxauth_legacyIdTokenClaims"] = self.setup_props["oxauth_legacyIdTokenClaims"]
        self.config["oxauth_openidScopeBackwardCompatibility"] = self.setup_props["oxauth_openidScopeBackwardCompatibility"]
        self.config["oxauth_openid_jwks_fn"] = "/etc/certs/oxauth-keys.json"
        self.config["oxauth_key_rotated_at"] = str(int(time.time()))
        self.secret["oxauthClient_encoded_pw"] = self.setup_props["oxauthClient_encoded_pw"]
        self.secret["oxauth_openid_jks_pass"] = self.setup_props["oxauth_openid_jks_pass"]
        self.secret["oxauth_jks_base64"] = self.encode_from_file("oxauth-keys.jks", mode="rb")

        jwks = self.backend.get_oxauth_jwks()
        self.secret["oxauth_openid_key_base64"] = generate_base64_contents(jwks)

    def scim_rs_ctx(self):
        self.config["scim_rs_client_id"] = self.setup_props["scim_rs_client_id"]
        self.config["scim_rs_client_jks_fn"] = self.setup_props["scim_rs_client_jks_fn"]
        self.config["scim_rs_client_jwks_fn"] = "/etc/certs/scim-rs-keys.json"
        self.config["scim_rs_client_cert_alg"] = "RS512"
        self.secret["scim_rs_client_jks_pass"] = self.setup_props["scim_rs_client_jks_pass"]
        self.secret["scim_rs_client_jks_pass_encoded"] = self.setup_props["scim_rs_client_jks_pass_encoded"]

        jwks = self.backend.get_client_jwks(self.config["scim_rs_client_id"])
        self.secret["scim_rs_client_base64_jwks"] = generate_base64_contents(jwks)

        for key in json.loads(jwks)["keys"]:
            if key["alg"] == self.config["scim_rs_client_cert_alg"]:
                self.config["scim_rs_client_cert_alias"] = key["kid"]
                break
        self.secret["scim_rs_jks_base64"] = self.encode_from_file("scim-rs.jks", mode="rb")

    def scim_rp_ctx(self):
        self.config["scim_rp_client_id"] = self.setup_props["scim_rp_client_id"]
        self.config["scim_resource_oxid"] = self.setup_props["scim_resource_oxid"]
        self.config["scim_rp_client_jks_fn"] = "/etc/certs/scim-rp.jks"
        self.config["scim_rp_client_jwks_fn"] = "/etc/certs/scim-rp-keys.json"
        self.secret["scim_rp_client_jks_pass"] = self.setup_props["scim_rp_client_jks_pass"]
        self.secret["scim_rp_client_jks_pass_encoded"] = encode_text(
            self.secret["scim_rp_client_jks_pass"],
            self.secret["encoded_salt"],
        ).decode()

        jwks = self.backend.get_client_jwks(self.config["scim_rp_client_id"])
        self.secret["scim_rp_client_base64_jwks"] = generate_base64_contents(jwks)
        self.secret["scim_rp_jks_base64"] = self.encode_from_file("scim-rp.jks", mode="rb")

    def passport_rs_ctx(self):
        # NOTE: passport rs may not be installed hence no data in setup.properties nor persistence
        self.config["passport_rs_client_id"] = self.setup_props.get("passport_rs_client_id", f"1501.{uuid.uuid4()}")
        self.config["passport_rs_client_jks_fn"] = self.setup_props["passport_rs_client_jks_fn"]
        self.config["passport_rs_client_jwks_fn"] = self.setup_props.get("passport_rs_client_jwks_fn", "/etc/certs/passport-rs-keys.json")
        self.config["passport_rs_client_cert_alg"] = self.setup_props.get("passport_rs_client_cert_alg", "RS512")
        self.config["passport_resource_id"] = self.setup_props.get("passport_resource_id", f"1504.{uuid.uuid4()}")
        self.secret["passport_rs_client_jks_pass"] = self.setup_props.get("passport_rs_client_jks_pass", get_random_chars())
        self.secret["passport_rs_client_jks_pass_encoded"] = self.setup_props.get(
            "passport_rs_client_jks_pass_encoded",
            encode_text(self.secret["passport_rs_client_jks_pass"], self.secret["encoded_salt"]).decode()
        )

        jwks = self.backend.get_client_jwks(self.config["passport_rs_client_id"])
        if not jwks:
            jwks, err, retcode = generate_openid_keys(
                self.secret["passport_rs_client_jks_pass"],
                os.path.join(self.migration_dir, "passport-rs.jks"),
                os.path.join(self.migration_dir, "passport-rs-keys.json"),
                self.config["default_openid_jks_dn_name"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate Passport RS keys; reason={err.decode()}")
            jwks = jwks.decode()

        self.secret["passport_rs_client_base64_jwks"] = generate_base64_contents(jwks)
        for key in json.loads(jwks)["keys"]:
            if key["alg"] == self.config["passport_rs_client_cert_alg"]:
                self.config["passport_rs_client_cert_alias"] = key["kid"]
                break
        self.secret["passport_rs_jks_base64"] = self.encode_from_file("passport-rs.jks", mode="rb")

    def passport_rp_ctx(self):
        self.config["passport_rp_client_id"] = self.setup_props.get("passport_rp_client_id", f"1502.{uuid.uuid4()}")
        self.config["passport_rp_ii_client_id"] = self.setup_props.get("passport_rp_ii_client_id", f"1503.{uuid.uuid4()}")
        self.config["passport_rp_client_jks_fn"] = self.setup_props["passport_rp_client_jks_fn"]
        self.config["passport_rp_client_jwks_fn"] = self.setup_props.get("passport_rp_client_jwks_fn", "/etc/certs/passport-rp-keys.json")
        self.config["passport_rp_client_cert_fn"] = self.setup_props["passport_rp_client_cert_fn"]
        self.config["passport_rp_client_cert_alg"] = self.setup_props["passport_rp_client_cert_alg"]
        self.secret["passport_rp_client_jks_pass"] = self.setup_props["passport_rp_client_jks_pass"]

        jwks = self.backend.get_client_jwks(self.config["passport_rp_client_id"])
        if not jwks:
            jwks, err, retcode = generate_openid_keys(
                self.secret["passport_rp_client_jks_pass"],
                os.path.join(self.migration_dir, "passport-rp.jks"),
                os.path.join(self.migration_dir, "passport-rp-keys.json"),
                self.config["default_openid_jks_dn_name"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate Passport RP keys; reason={err.decode()}")
            jwks = jwks.decode()

        self.secret["passport_rp_client_base64_jwks"] = generate_base64_contents(jwks)
        for key in json.loads(jwks)["keys"]:
            if key["alg"] == self.config["passport_rp_client_cert_alg"]:
                self.config["passport_rp_client_cert_alias"] = key["kid"]
                break
        self.secret["passport_rp_jks_base64"] = self.encode_from_file("passport-rp.jks", mode="rb")

        client_cert_fn = os.path.join(self.migration_dir, os.path.basename(self.config["passport_rp_client_cert_fn"]))
        _, err, retcode = export_openid_keys(
            os.path.join(self.migration_dir, os.path.basename(self.config["passport_rp_client_jks_fn"])),
            self.secret["passport_rp_client_jks_pass"],
            self.config["passport_rp_client_cert_alias"],
            client_cert_fn,
        )
        if retcode != 0:
            raise RuntimeError(f"Unable to generate Passport RP client cert; reason={err.decode()}")

        self.secret["passport_rp_client_cert_base64"] = self.encode_from_file(os.path.basename(client_cert_fn))

    def passport_sp_ctx(self):
        self.config["passportSpTLSCACert"] = self.setup_props["passportSpTLSCACert"]
        self.config["passportSpTLSCert"] = self.setup_props["passportSpTLSCert"]
        self.config["passportSpTLSKey"] = self.setup_props["passportSpTLSKey"]
        self.secret["passportSpKeyPass"] = self.setup_props["passportSpKeyPass"]
        self.config["passportSpJksFn"] = self.setup_props["passportSpJksFn"]
        self.secret["passportSpJksPass"] = self.setup_props["passportSpJksPass"]
        self.secret["passport_sp_cert_base64"] = self.encode_from_file(os.path.basename(self.config["passportSpTLSCert"]))
        self.secret["passport_sp_key_base64"] = self.encode_from_file(os.path.basename(self.config["passportSpTLSKey"]))

    def oxshibboleth_ctx(self):
        self.config["idp_client_id"] = self.setup_props["idp_client_id"]
        self.config["shibJksFn"] = self.setup_props["shibJksFn"]
        self.config["shibboleth_version"] = self.setup_props["shibboleth_version"]  # , "v3")
        self.config["idp3Folder"] = self.setup_props["idp3Folder"]
        self.secret["idpClient_encoded_pw"] = self.setup_props["idpClient_encoded_pw"]
        self.secret["shibJksPass"] = self.setup_props["shibJksPass"]
        self.secret["encoded_shib_jks_pw"] = self.setup_props["encoded_shib_jks_pw"]
        self.secret["shibIDP_cert"] = self.encode_from_file("shibIDP.crt")
        self.secret["shibIDP_key"] = self.encode_from_file("shibIDP.key")
        self.secret["shibIDP_jks_base64"] = self.encode_from_file(os.path.basename(self.config["shibJksFn"]), mode="rb")
        self.secret["idp3SigningCertificateText"] = self.from_file("idp-signing.crt")
        self.secret["idp3SigningKeyText"] = self.from_file("idp-signing.key")
        self.secret["idp3EncryptionCertificateText"] = self.from_file("idp-encryption.crt")
        self.secret["idp3EncryptionKeyText"] = self.from_file("idp-encryption.key")

        sealer_jks_fn = os.path.join(self.migration_dir, "sealer.jks")
        sealer_kver_fn = os.path.join(self.migration_dir, "sealer.kver")

        if not os.path.isfile(sealer_jks_fn) or os.path.isfile(sealer_kver_fn):
            _, err, retcode = gen_idp3_key(
                self.secret["shibJksPass"],
                sealer_jks_fn,
                sealer_kver_fn,
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate Shibboleth sealer; reason={err.decode()}")

        self.secret["sealer_jks_base64"] = self.encode_from_file(os.path.basename(sealer_jks_fn), mode="rb")
        self.secret["sealer_kver_base64"] = self.encode_from_file(os.path.basename(sealer_kver_fn), mode="rb")

    def oxtrust_api_rs_ctx(self):
        self.config["api_rs_client_jks_fn"] = self.setup_props["api_rs_client_jks_fn"]
        self.config["api_rs_client_jwks_fn"] = "/etc/certs/api-rs-keys.json"
        self.config["api_rs_client_cert_alg"] = "RS512"
        self.config["oxtrust_resource_server_client_id"] = self.setup_props["oxtrust_resource_server_client_id"]
        self.config["oxtrust_resource_id"] = self.setup_props["oxtrust_resource_id"]

        self.secret["api_rs_client_jks_pass"] = self.setup_props["api_rs_client_jks_pass"]
        self.secret["api_rs_client_jks_pass_encoded"] = self.setup_props["api_rs_client_jks_pass_encoded"]

        jwks = self.backend.get_client_jwks(self.config["oxtrust_resource_server_client_id"])
        if not jwks:
            jwks, err, retcode = generate_openid_keys(
                self.secret["api_rs_client_jks_pass"],
                os.path.join(self.migration_dir, "api-rs.jks"),
                os.path.join(self.migration_dir, "api-rs-keys.json"),
                self.config["default_openid_jks_dn_name"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate oxTrust API RS keys; reason={err.decode()}")
            jwks = jwks.decode()

        self.secret["api_rs_client_base64_jwks"] = generate_base64_contents(jwks)

        for key in json.loads(jwks)["keys"]:
            if key["alg"] == self.config["api_rs_client_cert_alg"]:
                self.config["api_rs_client_cert_alias"] = key["kid"]
                break
        self.secret["api_rs_jks_base64"] = self.encode_from_file("api-rs.jks", mode="rb")

    def oxtrust_api_rp_ctx(self):
        self.config["api_rp_client_jks_fn"] = self.setup_props["api_rp_client_jks_fn"]
        self.config["api_rp_client_jwks_fn"] = "/etc/certs/api-rp-keys.json"
        self.config["oxtrust_requesting_party_client_id"] = self.setup_props["oxtrust_requesting_party_client_id"]

        self.secret["api_rp_client_jks_pass"] = self.setup_props["api_rp_client_jks_pass"]
        self.secret["api_rp_client_jks_pass_encoded"] = self.setup_props["api_rp_client_jks_pass_encoded"]

        jwks = self.backend.get_client_jwks(self.config["oxtrust_requesting_party_client_id"])
        if not jwks:
            jwks, err, retcode = generate_openid_keys(
                self.secret["api_rp_client_jks_pass"],
                os.path.join(self.migration_dir, "api-rp.jks"),
                os.path.join(self.migration_dir, "api-rp-keys.json"),
                self.config["default_openid_jks_dn_name"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate oxTrust API RP keys; reason={err.decode()}")
            jwks = jwks.decode()

        self.secret["api_rp_client_base64_jwks"] = generate_base64_contents(jwks)
        self.secret["api_rp_jks_base64"] = self.encode_from_file("api-rp.jks", mode="rb")

    def oxtrust_api_client_ctx(self):
        self.config["api_test_client_id"] = f"0008-{uuid.uuid4()}"
        self.secret["api_test_client_secret"] = get_random_chars(24)

    def radius_ctx(self):
        self.config["gluu_radius_client_id"] = self.setup_props["gluu_radius_client_id"]
        self.secret["gluu_ro_encoded_pw"] = self.setup_props["gluu_ro_encoded_pw"]

        # radius_jwt_pass in setup.properties is plain text
        jwt_pass = self.setup_props["radius_jwt_pass"]
        self.secret["radius_jwt_pass"] = encode_text(jwt_pass, self.secret["encoded_salt"]).decode()

        jwks = self.backend.get_client_jwks(self.config["gluu_radius_client_id"])
        if not jwks:
            jwks, err, retcode = generate_openid_keys(
                jwt_pass,
                os.path.join(self.migration_dir, "gluu-radius.jks"),
                os.path.join(self.migration_dir, "gluu-radius.keys"),
                self.config["default_openid_jks_dn_name"],
            )
            if retcode != 0:
                raise RuntimeError(f"Unable to generate Gluu Radius keys; reason={err.decode()}")
            jwks = jwks.decode()

        for key in json.loads(jwks)["keys"]:
            if key["alg"] == "RS512":
                self.config["radius_jwt_keyId"] = key["kid"]
                break

        self.secret["gluu_ro_client_base64_jwks"] = generate_base64_contents(jwks)
        self.secret["radius_jks_base64"] = self.encode_from_file("gluu-radius.jks", mode="rb")

    def scim_client_ctx(self):
        self.config["scim_test_client_id"] = f"0008-{uuid.uuid4()}"
        self.secret["scim_test_client_secret"] = get_random_chars(24)

    def couchbase_ctx(self):
        self.config["couchbaseTrustStoreFn"] = self.setup_props["couchbaseTrustStoreFn"]
        self.secret["couchbase_shib_user_password"] = self.setup_props["couchbaseShibUserPassword"]

    def redis_ctx(self):
        self.secret["redis_pw"] = self.get_redis_password()

    def nginx_ctx(self):
        # CE uses httpd.crt and httpd.key
        with open(os.path.join(self.migration_dir, "httpd.crt")) as f:
            self.secret["ssl_cert"] = f.read()
        with open(os.path.join(self.migration_dir, "httpd.key")) as f:
            self.secret["ssl_key"] = f.read()

    def migrate(self):
        logger.info("Migrating config and secret from Community Edition manifests")

        self.base_ctx()
        self.nginx_ctx()
        self.ldap_ctx()
        self.redis_ctx()
        self.oxauth_ctx()
        self.scim_rs_ctx()
        self.scim_rp_ctx()
        self.passport_rs_ctx()
        self.passport_rp_ctx()
        self.passport_sp_ctx()
        self.oxshibboleth_ctx()
        self.oxtrust_api_rs_ctx()
        self.oxtrust_api_rp_ctx()
        self.oxtrust_api_client_ctx()
        self.radius_ctx()
        self.scim_client_ctx()
        self.couchbase_ctx()

        # finalize
        return {"_config": self.config, "_secret": self.secret}
