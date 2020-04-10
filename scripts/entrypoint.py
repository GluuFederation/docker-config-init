import json
import logging.config
import os
import random
import time
import uuid
from functools import partial

import click

from pygluu.containerlib import get_manager
from pygluu.containerlib import wait_for
from pygluu.containerlib.utils import get_random_chars
from pygluu.containerlib.utils import get_sys_random_chars
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import safe_render
from pygluu.containerlib.utils import ldap_encode

from parameter import params_from_file
from settings import LOGGING_CONFIG

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 RSA1_5 RSA-OAEP"
ENC_KEYS = SIG_KEYS

DEFAULT_CONFIG_FILE = "/app/db/config.json"
DEFAULT_SECRET_FILE = "/app/db/secret.json"
DEFAULT_GENERATE_FILE = "/app/db/generate.json"

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")

manager = get_manager()


def encode_template(fn, ctx, base_dir="/app/templates"):
    path = os.path.join(base_dir, fn)
    # ctx is nested which has `config` and `secret` keys
    data = {}
    for _, v in ctx.items():
        data.update(v)
    with open(path) as f:
        return generate_base64_contents(safe_render(f.read(), data))


def generate_openid_keys(passwd, jks_path, jwks_path, dn, exp=365):
    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-jar", "/app/javalibs/oxauth-client.jar",
        "-enc_keys", ENC_KEYS,
        "-sig_keys", SIG_KEYS,
        "-dnname", "{!r}".format(dn),
        "-expiration", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])
    out, err, retcode = exec_cmd(cmd)
    if retcode == 0:
        with open(jwks_path, "w") as f:
            f.write(str(out))
    return out, err, retcode


def export_openid_keys(keystore, keypasswd, alias, export_file):
    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-cp /app/javalibs/oxauth-client.jar",
        "org.gluu.oxauth.util.KeyExporter",
        "-keystore {}".format(keystore),
        "-keypasswd {}".format(keypasswd),
        "-alias {}".format(alias),
        "-exportfile {}".format(export_file),
    ])
    return exec_cmd(cmd)


def generate_pkcs12(suffix, passwd, hostname):
    # Convert key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(hostname),
        "-passout pass:{}".format(passwd),
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate PKCS12 file; reason={}".format(err)


class CtxGenerator(object):
    def __init__(self, params, manager=None):
        self.params = params
        self.ctx = {"config": {}, "secret": {}}
        # self.manager = manager
        # self._config_ctx = manager.config.all()
        # self._secret_ctx = manager.secret.all()

#     def _set_config(self):
#         overwrite_all = as_boolean(os.environ.get("GLUU_OVERWRITE_ALL", False))
#         if overwrite_all:
#             logger.info("updating {} {!r}".format(manager.config.type, key))
#             return value

#         # check existing value first
#         _value = manager.config.get(key)
#         if _value:
#             logger.info("ignoring {} {!r}".format(ctx_manager.adapter.type, key))
#             return _value

#         logger.info("adding {} {!r}".format(ctx_manager.adapter.type, key))
#         return value

    def base_ctx(self):
        self.ctx["secret"]["encoded_salt"] = get_or_set_secret("encoded_salt", get_random_chars(24))
        self.ctx["config"]["orgName"] = get_or_set_config("orgName", self.params["org_name"])
        self.ctx["config"]["country_code"] = get_or_set_config("country_code", self.params["country_code"])
        self.ctx["config"]["state"] = get_or_set_config("state", self.params["state"])
        self.ctx["config"]["city"] = get_or_set_config("city", self.params["city"])
        self.ctx["config"]["hostname"] = get_or_set_config("hostname", self.params["hostname"])
        self.ctx["config"]["admin_email"] = get_or_set_config("admin_email", self.params["email"])
        self.ctx["config"]["default_openid_jks_dn_name"] = get_or_set_config(
            "default_openid_jks_dn_name",
            "CN=oxAuth CA Certificates",
        )
        self.ctx["secret"]["pairwiseCalculationKey"] = get_or_set_secret(
            "pairwiseCalculationKey",
            get_sys_random_chars(random.randint(20, 30)),
        )
        self.ctx["secret"]["pairwiseCalculationSalt"] = get_or_set_secret(
            "pairwiseCalculationSalt",
            get_sys_random_chars(random.randint(20, 30)),
        )
        self.ctx["config"]["jetty_base"] = get_or_set_config("jetty_base", "/opt/gluu/jetty")
        self.ctx["config"]["fido2ConfigFolder"] = get_or_set_config("fido2ConfigFolder", "/etc/gluu/conf/fido2")
        self.ctx["config"]["admin_inum"] = get_or_set_config("admin_inum", "{}".format(uuid.uuid4()))
        self.ctx["secret"]["encoded_oxtrust_admin_password"] = get_or_set_secret(
            "encoded_oxtrust_admin_password",
            ldap_encode(self.params["admin_pw"]),
        )

    def ldap_ctx(self):
        # self.ctx["secret"]["encoded_ldap_pw"] = get_or_set_secret("encoded_ldap_pw", ldap_encode(self.params["admin_pw"]))
        self.ctx["secret"]["encoded_ox_ldap_pw"] = get_or_set_secret(
            "encoded_ox_ldap_pw",
            encode_text(self.params["ldap_pw"], self.ctx["secret"]["encoded_salt"]),
        )
        self.ctx["config"]["ldap_init_host"] = get_or_set_config("ldap_init_host", "localhost")
        self.ctx["config"]["ldap_init_port"] = int(get_or_set_config("ldap_init_port", 1636))
        self.ctx["config"]["ldap_port"] = int(get_or_set_config("ldap_port", 1389))
        self.ctx["config"]["ldaps_port"] = int(get_or_set_config("ldaps_port", 1636))
        self.ctx["config"]["ldap_binddn"] = get_or_set_config("ldap_binddn", "cn=directory manager")
        self.ctx["config"]["ldap_site_binddn"] = get_or_set_config("ldap_site_binddn", "cn=directory manager")
        self.ctx["secret"]["ldap_truststore_pass"] = get_or_set_secret(
            "ldap_truststore_pass",
            get_random_chars(),
        )
        self.ctx["config"]["ldapTrustStoreFn"] = get_or_set_config("ldapTrustStoreFn", "/etc/certs/opendj.pkcs12")

        generate_ssl_certkey(
            "opendj",
            self.ctx["secret"]["ldap_truststore_pass"],
            self.ctx["config"]["admin_email"],
            self.ctx["config"]["hostname"],
            self.ctx["config"]["orgName"],
            self.ctx["config"]["country_code"],
            self.ctx["config"]["state"],
            self.ctx["config"]["city"],
        )
        with open("/etc/certs/opendj.pem", "w") as fw:
            with open("/etc/certs/opendj.crt") as fr:
                ldap_ssl_cert = fr.read()

                self.ctx["secret"]["ldap_ssl_cert"] = get_or_set_secret(
                    "ldap_ssl_cert",
                    encode_text(ldap_ssl_cert, self.ctx["secret"]["encoded_salt"]),
                )

            with open("/etc/certs/opendj.key") as fr:
                ldap_ssl_key = fr.read()

                self.ctx["secret"]["ldap_ssl_key"] = get_or_set_secret(
                    "ldap_ssl_key",
                    encode_text(ldap_ssl_key, self.ctx["secret"]["encoded_salt"]),
                )

            ldap_ssl_cacert = "".join([ldap_ssl_cert, ldap_ssl_key])
            fw.write(ldap_ssl_cacert)

            self.ctx["secret"]["ldap_ssl_cacert"] = get_or_set_secret(
                "ldap_ssl_cacert",
                encode_text(ldap_ssl_cacert, self.ctx["secret"]["encoded_salt"]),
            )

        generate_pkcs12(
            "opendj",
            self.ctx["secret"]["ldap_truststore_pass"],
            self.ctx["config"]["hostname"],
        )
        with open(self.ctx["config"]["ldapTrustStoreFn"], "rb") as fr:
            self.ctx["secret"]["ldap_pkcs12_base64"] = get_or_set_secret(
                "ldap_pkcs12_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"]),
            )

        self.ctx["secret"]["encoded_ldapTrustStorePass"] = get_or_set_secret(
            "encoded_ldapTrustStorePass",
            encode_text(self.ctx["secret"]["ldap_truststore_pass"], self.ctx["secret"]["encoded_salt"]),
        )

    def redis_ctx(self):
        self.ctx["secret"]["redis_pw"] = get_or_set_secret("redis_pw", self.params.get("redis_pw", ""))

    def oxauth_ctx(self):
        self.ctx["config"]["oxauth_client_id"] = get_or_set_config(
            "oxauth_client_id",
            "1001.{}".format(uuid.uuid4()),
        )
        self.ctx["secret"]["oxauthClient_encoded_pw"] = get_or_set_secret(
            "oxauthClient_encoded_pw",
            encode_text(get_random_chars(), self.ctx["secret"]["encoded_salt"]),
        )
        self.ctx["config"]["oxauth_openid_jks_fn"] = get_or_set_config(
            "oxauth_openid_jks_fn",
            "/etc/certs/oxauth-keys.jks",
        )
        self.ctx["secret"]["oxauth_openid_jks_pass"] = get_or_set_secret(
            "oxauth_openid_jks_pass",
            get_random_chars(),
        )
        self.ctx["config"]["oxauth_openid_jwks_fn"] = get_or_set_config(
            "oxauth_openid_jwks_fn",
            "/etc/certs/oxauth-keys.json",
        )
        self.ctx["config"]["oxauth_legacyIdTokenClaims"] = get_or_set_config(
            "oxauth_legacyIdTokenClaims",
            "true",
        )
        self.ctx["config"]["oxauth_openidScopeBackwardCompatibility"] = get_or_set_config(
            "oxauth_openidScopeBackwardCompatibility",
            "true",
        )

        _, err, retcode = generate_openid_keys(
            self.ctx["secret"]["oxauth_openid_jks_pass"],
            self.ctx["config"]["oxauth_openid_jks_fn"],
            self.ctx["config"]["oxauth_openid_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
            exp=2,
        )
        if retcode != 0:
            logger.error("Unable to generate oxAuth keys; reason={}".format(err))
            click.Abort()

        basedir, fn = os.path.split(self.ctx["config"]["oxauth_openid_jwks_fn"])
        self.ctx["secret"]["oxauth_openid_key_base64"] = get_or_set_secret(
            "oxauth_openid_key_base64",
            encode_template(fn, self.ctx, basedir),
        )

        # oxAuth keys
        self.ctx["config"]["oxauth_key_rotated_at"] = int(get_or_set_config(
            "oxauth_key_rotated_at",
            int(time.time()),
        ))

        with open(self.ctx["config"]["oxauth_openid_jks_fn"], "rb") as fr:
            self.ctx["secret"]["oxauth_jks_base64"] = get_or_set_secret(
                "oxauth_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"])
            )

    def scim_rs_ctx(self):
        self.ctx["config"]["scim_rs_client_id"] = get_or_set_config(
            "scim_rs_client_id",
            "1201.{}".format(uuid.uuid4()),
        )

        self.ctx["config"]["scim_rs_client_jks_fn"] = get_or_set_config(
            "scim_rs_client_jks_fn", "/etc/certs/scim-rs.jks")

        self.ctx["config"]["scim_rs_client_jwks_fn"] = get_or_set_config(
            "scim_rs_client_jwks_fn", "/etc/certs/scim-rs-keys.json")

        self.ctx["secret"]["scim_rs_client_jks_pass"] = get_or_set_secret(
            "scim_rs_client_jks_pass", get_random_chars())

        self.ctx["secret"]["scim_rs_client_jks_pass_encoded"] = get_or_set_secret(
            "scim_rs_client_jks_pass_encoded",
            encode_text(self.ctx["secret"]["scim_rs_client_jks_pass"], self.ctx["secret"]["encoded_salt"]),
        )

        out, err, retcode = generate_openid_keys(
            self.ctx["secret"]["scim_rs_client_jks_pass"],
            self.ctx["config"]["scim_rs_client_jks_fn"],
            self.ctx["config"]["scim_rs_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if retcode != 0:
            logger.error("Unable to generate SCIM RS keys; reason={}".format(err))
            click.Abort()

        self.ctx["config"]["scim_rs_client_cert_alg"] = get_or_set_config(
            "scim_rs_client_cert_alg", "RS512")

        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == self.ctx["config"]["scim_rs_client_cert_alg"]:
                cert_alias = key["kid"]
                break

        basedir, fn = os.path.split(self.ctx["config"]["scim_rs_client_jwks_fn"])
        self.ctx["secret"]["scim_rs_client_base64_jwks"] = get_or_set_secret(
            "scim_rs_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        self.ctx["config"]["scim_rs_client_cert_alias"] = get_or_set_config(
            "scim_rs_client_cert_alias", cert_alias
        )

        with open(self.ctx["config"]["scim_rs_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["scim_rs_jks_base64"] = get_or_set_secret(
                "scim_rs_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"]),
            )

    def scim_rp_ctx(self):
        self.ctx["config"]["scim_rp_client_id"] = get_or_set_config(
            "scim_rp_client_id",
            "1202.{}".format(uuid.uuid4()),
        )

        self.ctx["config"]["scim_rp_client_jks_fn"] = get_or_set_config(
            "scim_rp_client_jks_fn", "/etc/certs/scim-rp.jks")

        self.ctx["config"]["scim_rp_client_jwks_fn"] = get_or_set_config(
            "scim_rp_client_jwks_fn", "/etc/certs/scim-rp-keys.json")

        self.ctx["secret"]["scim_rp_client_jks_pass"] = get_or_set_secret(
            "scim_rp_client_jks_pass", get_random_chars())

        self.ctx["secret"]["scim_rp_client_jks_pass_encoded"] = get_or_set_secret(
            "scim_rp_client_jks_pass_encoded",
            encode_text(self.ctx["secret"]["scim_rp_client_jks_pass"], self.ctx["secret"]["encoded_salt"]),
        )

        _, err, retcode = generate_openid_keys(
            self.ctx["secret"]["scim_rp_client_jks_pass"],
            self.ctx["config"]["scim_rp_client_jks_fn"],
            self.ctx["config"]["scim_rp_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if retcode != 0:
            logger.error("Unable to generate SCIM RP keys; reason={}".format(err))
            click.Abort()

        basedir, fn = os.path.split(self.ctx["config"]["scim_rp_client_jwks_fn"])
        self.ctx["secret"]["scim_rp_client_base64_jwks"] = get_or_set_secret(
            "scim_rp_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        with open(self.ctx["config"]["scim_rp_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["scim_rp_jks_base64"] = get_or_set_secret(
                "scim_rp_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"]),
            )

        self.ctx["config"]["scim_resource_oxid"] = get_or_set_config(
            "scim_resource_oxid",
            "1203.{}".format(uuid.uuid4()),
        )

    def passport_rs_ctx(self):
        self.ctx["config"]["passport_rs_client_id"] = get_or_set_config(
            "passport_rs_client_id",
            "1501.{}".format(uuid.uuid4()),
        )

        self.ctx["config"]["passport_rs_client_jks_fn"] = get_or_set_config(
            "passport_rs_client_jks_fn", "/etc/certs/passport-rs.jks")

        self.ctx["config"]["passport_rs_client_jwks_fn"] = get_or_set_config(
            "passport_rs_client_jwks_fn", "/etc/certs/passport-rs-keys.json")

        self.ctx["secret"]["passport_rs_client_jks_pass"] = get_or_set_secret(
            "passport_rs_client_jks_pass", get_random_chars())

        self.ctx["secret"]["passport_rs_client_jks_pass_encoded"] = get_or_set_secret(
            "passport_rs_client_jks_pass_encoded",
            encode_text(self.ctx["secret"]["passport_rs_client_jks_pass"], self.ctx["secret"]["encoded_salt"]),
        )

        out, err, retcode = generate_openid_keys(
            self.ctx["secret"]["passport_rs_client_jks_pass"],
            self.ctx["config"]["passport_rs_client_jks_fn"],
            self.ctx["config"]["passport_rs_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if retcode != 0:
            logger.error("Unable to generate Passport RS keys; reason={}".format(err))
            click.Abort()

        self.ctx["config"]["passport_rs_client_cert_alg"] = get_or_set_config(
            "passport_rs_client_cert_alg", "RS512")

        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == self.ctx["config"]["passport_rs_client_cert_alg"]:
                cert_alias = key["kid"]
                break

        basedir, fn = os.path.split(self.ctx["config"]["passport_rs_client_jwks_fn"])
        self.ctx["secret"]["passport_rs_client_base64_jwks"] = get_or_set_secret(
            "passport_rs_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        self.ctx["config"]["passport_rs_client_cert_alias"] = get_or_set_config(
            "passport_rs_client_cert_alias", cert_alias
        )

        with open(self.ctx["config"]["passport_rs_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["passport_rs_jks_base64"] = get_or_set_secret(
                "passport_rs_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"])
            )

        self.ctx["config"]["passport_resource_id"] = get_or_set_config(
            "passport_resource_id",
            '1504.{}'.format(uuid.uuid4()),
        )

        self.ctx["config"]["passport_rs_client_cert_alias"] = get_or_set_config(
            "passport_rs_client_cert_alias", cert_alias
        )

    def passport_rp_ctx(self):
        self.ctx["config"]["passport_rp_client_id"] = get_or_set_config(
            "passport_rp_client_id",
            "1502.{}".format(uuid.uuid4()),
        )

        self.ctx["config"]["passport_rp_ii_client_id"] = get_or_set_config(
            "passport_rp_ii_client_id",
            "1503.{}".format(uuid.uuid4()),
        )

        self.ctx["secret"]["passport_rp_client_jks_pass"] = get_or_set_secret(
            "passport_rp_client_jks_pass", get_random_chars())

        self.ctx["config"]["passport_rp_client_jks_fn"] = get_or_set_config(
            "passport_rp_client_jks_fn", "/etc/certs/passport-rp.jks")

        self.ctx["config"]["passport_rp_client_jwks_fn"] = get_or_set_config(
            "passport_rp_client_jwks_fn", "/etc/certs/passport-rp-keys.json")

        self.ctx["config"]["passport_rp_client_cert_fn"] = get_or_set_config(
            "passport_rp_client_cert_fn", "/etc/certs/passport-rp.pem")

        self.ctx["config"]["passport_rp_client_cert_alg"] = get_or_set_config(
            "passport_rp_client_cert_alg", "RS512")

        out, err, code = generate_openid_keys(
            self.ctx["secret"]["passport_rp_client_jks_pass"],
            self.ctx["config"]["passport_rp_client_jks_fn"],
            self.ctx["config"]["passport_rp_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if code != 0:
            logger.error("Unable to generate Passport RP keys; reason={}".format(err))
            click.Abort()

        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == self.ctx["config"]["passport_rp_client_cert_alg"]:
                cert_alias = key["kid"]
                break

        _, err, retcode = export_openid_keys(
            self.ctx["config"]["passport_rp_client_jks_fn"],
            self.ctx["secret"]["passport_rp_client_jks_pass"],
            cert_alias,
            self.ctx["config"]["passport_rp_client_cert_fn"],
        )
        if retcode != 0:
            logger.error("Unable to generate Passport RP client cert; reason={}".format(err))
            click.Abort()

        basedir, fn = os.path.split(self.ctx["config"]["passport_rp_client_jwks_fn"])
        self.ctx["secret"]["passport_rp_client_base64_jwks"] = get_or_set_secret(
            "passport_rp_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        self.ctx["config"]["passport_rp_client_cert_alias"] = get_or_set_config(
            "passport_rp_client_cert_alias", cert_alias
        )

        with open(self.ctx["config"]["passport_rp_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["passport_rp_jks_base64"] = get_or_set_secret(
                "passport_rp_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"]),
            )

        with open(self.ctx["config"]["passport_rp_client_cert_fn"]) as fr:
            self.ctx["secret"]["passport_rp_client_cert_base64"] = get_or_set_secret(
                "passport_rp_client_cert_base64",
                encode_text(fr.read(), self.ctx["secret"]["encoded_salt"]),
            )

    def passport_sp_ctx(self):
        self.ctx["secret"]["passportSpKeyPass"] = get_or_set_secret("passportSpKeyPass", get_random_chars())

        self.ctx["config"]["passportSpTLSCACert"] = get_or_set_config("passportSpTLSCACert", '/etc/certs/passport-sp.pem')

        self.ctx["config"]["passportSpTLSCert"] = get_or_set_config("passportSpTLSCert", '/etc/certs/passport-sp.crt')

        self.ctx["config"]["passportSpTLSKey"] = get_or_set_config("passportSpTLSKey", '/etc/certs/passport-sp.key')

        self.ctx["secret"]["passportSpJksPass"] = get_or_set_secret("passportSpJksPass", get_random_chars())

        self.ctx["config"]["passportSpJksFn"] = get_or_set_config("passportSpJksFn", '/etc/certs/passport-sp.jks')

        generate_ssl_certkey(
            "passport-sp",
            self.ctx["secret"]["passportSpKeyPass"],
            self.ctx["config"]["admin_email"],
            self.ctx["config"]["hostname"],
            self.ctx["config"]["orgName"],
            self.ctx["config"]["country_code"],
            self.ctx["config"]["state"],
            self.ctx["config"]["city"],
        )
        with open(self.ctx["config"]["passportSpTLSCert"]) as f:
            self.ctx["secret"]["passport_sp_cert_base64"] = get_or_set_secret(
                "passport_sp_cert_base64",
                encode_text(f.read(), self.ctx["secret"]["encoded_salt"])
            )

        with open(self.ctx["config"]["passportSpTLSKey"]) as f:
            self.ctx["secret"]["passport_sp_key_base64"] = get_or_set_secret(
                "passport_sp_key_base64",
                encode_text(f.read(), self.ctx["secret"]["encoded_salt"])
            )

    def nginx_ctx(self):
        ssl_cert = "/etc/certs/gluu_https.crt"
        ssl_key = "/etc/certs/gluu_https.key"
        self.ctx["secret"]["ssl_cert_pass"] = get_or_set_secret("ssl_cert_pass", get_random_chars())

        # generate self-signed SSL cert and key only if they aren't exist
        if not(os.path.exists(ssl_cert) and os.path.exists(ssl_key)):
            generate_ssl_certkey(
                "gluu_https",
                self.ctx["secret"]["ssl_cert_pass"],
                self.ctx["config"]["admin_email"],
                self.ctx["config"]["hostname"],
                self.ctx["config"]["orgName"],
                self.ctx["config"]["country_code"],
                self.ctx["config"]["state"],
                self.ctx["config"]["city"],
            )

        with open(ssl_cert) as f:
            self.ctx["secret"]["ssl_cert"] = get_or_set_secret("ssl_cert", f.read())

        with open(ssl_key) as f:
            self.ctx["secret"]["ssl_key"] = get_or_set_secret("ssl_key", f.read())

    def oxshibboleth_ctx(self):
        self.ctx["config"]["idp_client_id"] = get_or_set_config(
            "idp_client_id",
            "1101.{}".format(uuid.uuid4()),
        )

        self.ctx["secret"]["idpClient_encoded_pw"] = get_or_set_secret(
            "idpClient_encoded_pw",
            encode_text(get_random_chars(), self.ctx["secret"]["encoded_salt"]),
        )

        self.ctx["config"]["shibJksFn"] = get_or_set_config("shibJksFn", "/etc/certs/shibIDP.jks")

        self.ctx["secret"]["shibJksPass"] = get_or_set_secret("shibJksPass", get_random_chars())

        self.ctx["secret"]["encoded_shib_jks_pw"] = get_or_set_secret(
            "encoded_shib_jks_pw",
            encode_text(self.ctx["secret"]["shibJksPass"], self.ctx["secret"]["encoded_salt"])
        )

        generate_ssl_certkey(
            "shibIDP",
            self.ctx["secret"]["shibJksPass"],
            self.ctx["config"]["admin_email"],
            self.ctx["config"]["hostname"],
            self.ctx["config"]["orgName"],
            self.ctx["config"]["country_code"],
            self.ctx["config"]["state"],
            self.ctx["config"]["city"],
        )

        generate_keystore("shibIDP", self.ctx["config"]["hostname"], self.ctx["secret"]["shibJksPass"])

        with open("/etc/certs/shibIDP.crt") as f:
            self.ctx["secret"]["shibIDP_cert"] = get_or_set_secret(
                "shibIDP_cert",
                encode_text(f.read(), self.ctx["secret"]["encoded_salt"])
            )

        with open("/etc/certs/shibIDP.key") as f:
            self.ctx["secret"]["shibIDP_key"] = get_or_set_secret(
                "shibIDP_key",
                encode_text(f.read(), self.ctx["secret"]["encoded_salt"])
            )

        with open(self.ctx["config"]["shibJksFn"], "rb") as f:
            self.ctx["secret"]["shibIDP_jks_base64"] = get_or_set_secret(
                "shibIDP_jks_base64",
                encode_text(str(f.read()), self.ctx["secret"]["encoded_salt"])
            )

        self.ctx["config"]["shibboleth_version"] = get_or_set_config("shibboleth_version", "v3")

        self.ctx["config"]["idp3Folder"] = get_or_set_config("idp3Folder", "/opt/shibboleth-idp")

        idp3_signing_cert = "/etc/certs/idp-signing.crt"

        idp3_signing_key = "/etc/certs/idp-signing.key"

        generate_ssl_certkey(
            "idp-signing",
            self.ctx["secret"]["shibJksPass"],
            self.ctx["config"]["admin_email"],
            self.ctx["config"]["hostname"],
            self.ctx["config"]["orgName"],
            self.ctx["config"]["country_code"],
            self.ctx["config"]["state"],
            self.ctx["config"]["city"],
        )

        with open(idp3_signing_cert) as f:
            self.ctx["secret"]["idp3SigningCertificateText"] = get_or_set_secret(
                "idp3SigningCertificateText", f.read())

        with open(idp3_signing_key) as f:
            self.ctx["secret"]["idp3SigningKeyText"] = get_or_set_secret(
                "idp3SigningKeyText", f.read())

        idp3_encryption_cert = "/etc/certs/idp-encryption.crt"

        idp3_encryption_key = "/etc/certs/idp-encryption.key"

        generate_ssl_certkey(
            "idp-encryption",
            self.ctx["secret"]["shibJksPass"],
            self.ctx["config"]["admin_email"],
            self.ctx["config"]["hostname"],
            self.ctx["config"]["orgName"],
            self.ctx["config"]["country_code"],
            self.ctx["config"]["state"],
            self.ctx["config"]["city"],
        )

        with open(idp3_encryption_cert) as f:
            self.ctx["secret"]["idp3EncryptionCertificateText"] = get_or_set_secret(
                "idp3EncryptionCertificateText", f.read())

        with open(idp3_encryption_key) as f:
            self.ctx["secret"]["idp3EncryptionKeyText"] = get_or_set_secret(
                "idp3EncryptionKeyText", f.read())

        _, err, code = gen_idp3_key(self.ctx["secret"]["shibJksPass"])
        if code != 0:
            logger.warninging(f"Unable to generate Shibboleth sealer; reason={err}")
            click.Abort()

        with open("/etc/certs/sealer.jks", "rb") as f:
            self.ctx["secret"]["sealer_jks_base64"] = get_or_set_secret(
                "sealer_jks_base64",
                encode_text(str(f.read()), self.ctx["secret"]["encoded_salt"])
            )

        with open("/etc/certs/sealer.kver") as f:
            self.ctx["secret"]["sealer_kver_base64"] = get_or_set_secret(
                "sealer_kver_base64",
                encode_text(f.read(), self.ctx["secret"]["encoded_salt"])
            )

    def oxtrust_api_rs_ctx(self):
        self.ctx["config"]["api_rs_client_jks_fn"] = get_or_set_config(
            "api_rs_client_jks_fn", "/etc/certs/api-rs.jks")

        self.ctx["config"]["api_rs_client_jwks_fn"] = get_or_set_config(
            "api_rs_client_jwks_fn", "/etc/certs/api-rs-keys.json")

        self.ctx["secret"]["api_rs_client_jks_pass"] = get_or_set_secret(
            "api_rs_client_jks_pass", get_random_chars(),
        )
        self.ctx["secret"]["api_rs_client_jks_pass_encoded"] = get_or_set_secret(
            "api_rs_client_jks_pass_encoded",
            encode_text(self.ctx["secret"]["api_rs_client_jks_pass"], self.ctx["secret"]["encoded_salt"]),
        )

        out, err, retcode = generate_openid_keys(
            self.ctx["secret"]["api_rs_client_jks_pass"],
            self.ctx["config"]["api_rs_client_jks_fn"],
            self.ctx["config"]["api_rs_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if retcode != 0:
            logger.error("Unable to generate oxTrust API RS keys; reason={}".format(err))
            click.Abort()

        self.ctx["config"]["api_rs_client_cert_alg"] = get_or_set_config(
            "api_rs_client_cert_alg", "RS512")

        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == self.ctx["config"]["api_rs_client_cert_alg"]:
                cert_alias = key["kid"]
                break

        basedir, fn = os.path.split(self.ctx["config"]["api_rs_client_jwks_fn"])
        self.ctx["secret"]["api_rs_client_base64_jwks"] = get_or_set_secret(
            "api_rs_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        self.ctx["config"]["api_rs_client_cert_alias"] = get_or_set_config(
            "api_rs_client_cert_alias", cert_alias
        )

        self.ctx["config"]["oxtrust_resource_server_client_id"] = get_or_set_config(
            "oxtrust_resource_server_client_id",
            '1401.{}'.format(uuid.uuid4()),
        )
        self.ctx["config"]["oxtrust_resource_id"] = get_or_set_config(
            "oxtrust_resource_id",
            '1403.{}'.format(uuid.uuid4()),
        )
        with open(self.ctx["config"]["api_rs_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["api_rs_jks_base64"] = get_or_set_secret(
                "api_rs_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"])
            )

    def oxtrust_api_rp_ctx(self):
        self.ctx["config"]["api_rp_client_jks_fn"] = get_or_set_config(
            "api_rp_client_jks_fn", "/etc/certs/api-rp.jks")

        self.ctx["config"]["api_rp_client_jwks_fn"] = get_or_set_config(
            "api_rp_client_jwks_fn", "/etc/certs/api-rp-keys.json")

        self.ctx["secret"]["api_rp_client_jks_pass"] = get_or_set_secret(
            "api_rp_client_jks_pass", get_random_chars(),
        )
        self.ctx["secret"]["api_rp_client_jks_pass_encoded"] = get_or_set_secret(
            "api_rp_client_jks_pass_encoded",
            encode_text(self.ctx["secret"]["api_rp_client_jks_pass"], self.ctx["secret"]["encoded_salt"]),
        )
        _, err, retcode = generate_openid_keys(
            self.ctx["secret"]["api_rp_client_jks_pass"],
            self.ctx["config"]["api_rp_client_jks_fn"],
            self.ctx["config"]["api_rp_client_jwks_fn"],
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if retcode != 0:
            logger.error("Unable to generate oxTrust API RP keys; reason={}".format(err))
            click.Abort()

        basedir, fn = os.path.split(self.ctx["config"]["api_rp_client_jwks_fn"])
        self.ctx["secret"]["api_rp_client_base64_jwks"] = get_or_set_secret(
            "api_rp_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

        self.ctx["config"]["oxtrust_requesting_party_client_id"] = get_or_set_config(
            "oxtrust_requesting_party_client_id",
            '1402.{}'.format(uuid.uuid4()),
        )

        with open(self.ctx["config"]["api_rp_client_jks_fn"], "rb") as fr:
            self.ctx["secret"]["api_rp_jks_base64"] = get_or_set_secret(
                "api_rp_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"])
            )

    def oxtrust_api_client_ctx(self):
        self.ctx["config"]["api_test_client_id"] = get_or_set_config(
            "api_test_client_id",
            "0008-{}".format(uuid.uuid4()),
        )
        self.ctx["secret"]["api_test_client_secret"] = get_or_set_secret(
            "api_test_client_secret",
            get_random_chars(24),
        )

    def radius_ctx(self):
        self.ctx["config"]["gluu_radius_client_id"] = get_or_set_config(
            "gluu_radius_client_id",
            '1701.{}'.format(uuid.uuid4()),
        )
        # self.ctx["config"]["ox_radius_client_id"] = get_or_set_config(
        #     "ox_radius_client_id",
        #     '0008-{}'.format(uuid.uuid4()),
        # )
        self.ctx["secret"]["gluu_ro_encoded_pw"] = get_or_set_secret(
            "gluu_ro_encoded_pw",
            encode_text(get_random_chars(), self.ctx["secret"]["encoded_salt"]),
        )

        radius_jwt_pass = get_random_chars()
        self.ctx["secret"]["radius_jwt_pass"] = get_or_set_secret(
            "radius_jwt_pass",
            encode_text(radius_jwt_pass, self.ctx["secret"]["encoded_salt"]),
        )

        out, err, code = generate_openid_keys(
            radius_jwt_pass,
            "/etc/certs/gluu-radius.jks",
            "/etc/certs/gluu-radius.keys",
            self.ctx["config"]["default_openid_jks_dn_name"],
        )
        if code != 0:
            logger.error("Unable to generate Gluu Radius keys; reason={}".format(err))
            click.Abort()

        for key in json.loads(out)["keys"]:
            if key["alg"] == "RS512":
                self.ctx["config"]["radius_jwt_keyId"] = key["kid"]
                break

        with open("/etc/certs/gluu-radius.jks", "rb") as fr:
            self.ctx["secret"]["radius_jks_base64"] = get_or_set_secret(
                "radius_jks_base64",
                encode_text(str(fr.read()), self.ctx["secret"]["encoded_salt"])
            )

        basedir, fn = os.path.split("/etc/certs/gluu-radius.keys")
        self.ctx["secret"]["gluu_ro_client_base64_jwks"] = get_or_set_secret(
            "gluu_ro_client_base64_jwks",
            encode_template(fn, self.ctx, basedir),
        )

    def scim_client_ctx(self):
        self.ctx["config"]["scim_test_client_id"] = get_or_set_config(
            "scim_test_client_id",
            "0008-{}".format(uuid.uuid4()),
        )
        self.ctx["secret"]["scim_test_client_secret"] = get_or_set_secret(
            "scim_test_client_secret",
            get_random_chars(24),
        )

    def couchbase_ctx(self):
        self.ctx["config"]["couchbaseTrustStoreFn"] = get_or_set_config(
            "couchbaseTrustStoreFn", "/etc/certs/couchbase.pkcs12",
        )
        self.ctx["secret"]["couchbase_shib_user_password"] = get_random_chars()

    def generate(self):
        self.base_ctx()
        self.ldap_ctx()
        self.redis_ctx()
        self.oxauth_ctx()
        self.scim_rs_ctx()
        self.scim_rp_ctx()
        self.passport_rs_ctx()
        self.passport_rp_ctx()
        self.passport_sp_ctx()
        self.nginx_ctx()
        self.oxshibboleth_ctx()
        self.oxtrust_api_rs_ctx()
        self.oxtrust_api_rp_ctx()
        self.oxtrust_api_client_ctx()
        self.radius_ctx()
        self.scim_client_ctx()
        self.couchbase_ctx()
        # populated config
        return self.ctx


def generate_ssl_certkey(suffix, passwd, email, hostname, org_name,
                         country_code, state, city):
    # create key with password
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "genrsa -des3",
        "-out /etc/certs/{}.key.orig".format(suffix),
        "-passout pass:'{}' 2048".format(passwd),
    ]))
    assert retcode == 0, "Failed to generate SSL key with password; reason={}".format(err)

    # create .key
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "rsa",
        "-in /etc/certs/{}.key.orig".format(suffix),
        "-passin pass:'{}'".format(passwd),
        "-out /etc/certs/{}.key".format(suffix),
    ]))
    assert retcode == 0, "Failed to generate SSL key; reason={}".format(err)

    # create .csr
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "req",
        "-new",
        "-key /etc/certs/{}.key".format(suffix),
        "-out /etc/certs/{}.csr".format(suffix),
        """-subj /C="{}"/ST="{}"/L="{}"/O="{}"/CN="{}"/emailAddress='{}'""".format(country_code, state, city, org_name, hostname, email),

    ]))
    assert retcode == 0, "Failed to generate SSL CSR; reason={}".format(err)

    # create .crt
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "x509",
        "-req",
        "-days 365",
        "-in /etc/certs/{}.csr".format(suffix),
        "-signkey /etc/certs/{}.key".format(suffix),
        "-out /etc/certs/{}.crt".format(suffix),
    ]))
    assert retcode == 0, "Failed to generate SSL cert; reason={}".format(err)

    # return the paths
    return "/etc/certs/{}.crt".format(suffix), \
           "/etc/certs/{}.key".format(suffix)


def validate_country_code(ctx, param, value):
    if len(value) != 2:
        raise click.BadParameter("Country code must be two characters")
    return value


def generate_keystore(suffix, hostname, keypasswd):
    # converts key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(hostname),
        "-passout pass:'{}'".format(keypasswd),
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate PKCS12 keystore; reason={}".format(err)

    # imports p12 to keystore
    cmd = " ".join([
        "keytool",
        "-importkeystore",
        "-srckeystore /etc/certs/{}.pkcs12".format(suffix),
        "-srcstorepass {}".format(keypasswd),
        "-srcstoretype PKCS12",
        "-destkeystore /etc/certs/{}.jks".format(suffix),
        "-deststorepass {}".format(keypasswd),
        "-deststoretype JKS",
        "-keyalg RSA",
        "-noprompt",
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate JKS keystore; reason={}".format(err)


def gen_idp3_key(storepass):
    cmd = " ".join([
        "java",
        "-classpath '/app/javalibs/*'",
        "net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategyTool",
        "--storefile /etc/certs/sealer.jks",
        "--versionfile /etc/certs/sealer.kver",
        "--alias secret",
        "--storepass {}".format(storepass),
    ])
    return exec_cmd(cmd)


def _get_or_set(key, value, ctx_manager):
    overwrite_all = as_boolean(os.environ.get("GLUU_OVERWRITE_ALL", False))
    if overwrite_all:
        logger.info("updating {} {!r}".format(ctx_manager.adapter.type, key))
        return value

    # check existing value first
    _value = ctx_manager.get(key)
    if _value:
        logger.info("ignoring {} {!r}".format(ctx_manager.adapter.type, key))
        return _value

    logger.info("adding {} {!r}".format(ctx_manager.adapter.type, key))
    return value


#: Gets value of existing config or sets a new one
get_or_set_config = partial(_get_or_set, ctx_manager=manager.config)

#: Gets value of existing secret or sets a new one
get_or_set_secret = partial(_get_or_set, ctx_manager=manager.secret)


def _save_generated_ctx(ctx_manager, filepath, data):
    logger.info("Saving {} to backend.".format(ctx_manager.adapter.type))

    for k, v in data.items():
        ctx_manager.set(k, v)


def _load_from_file(ctx_manager, filepath):
    logger.info("Loading {} from {}.".format(
        ctx_manager.adapter.type, filepath))

    with open(filepath, "r") as f:
        data = json.loads(f.read())

    if "_{}".format(ctx_manager.adapter.type) not in data:
        logger.warning("Missing '_{}' key.".format(ctx_manager.adapter.type))
        return

    # tolerancy before checking existing key
    time.sleep(5)
    for k, v in data["_{}".format(ctx_manager.adapter.type)].items():
        v = _get_or_set(k, v, ctx_manager)
        ctx_manager.set(k, v)


def _dump_to_file(ctx_manager, filepath):
    logger.info("Saving {} to {}.".format(
        ctx_manager.adapter.type, filepath))

    data = {"_{}".format(ctx_manager.adapter.type): ctx_manager.all()}
    data = json.dumps(data, sort_keys=True, indent=4)
    with open(filepath, "w") as f:
        f.write(data)

# ============
# CLI commands
# ============


@click.group()
def cli():
    pass


@cli.command()
@click.option(
    "--generate-file",
    type=click.Path(exists=False),
    help="Absolute path to file containing parameters for generating config and secret",
    default=DEFAULT_GENERATE_FILE,
    show_default=True,
)
@click.option(
    "--config-file",
    type=click.Path(exists=False),
    help="Absolute path to file contains config",
    default=DEFAULT_CONFIG_FILE,
    show_default=True,
)
@click.option(
    "--secret-file",
    type=click.Path(exists=False),
    help="Absolute path to file contains secret",
    default=DEFAULT_SECRET_FILE,
    show_default=True,
)
def load(generate_file, config_file, secret_file):
    """Loads config and secret from JSON files (generate if not exist).
    """
    config_file_found = os.path.isfile(config_file)
    secret_file_found = os.path.isfile(secret_file)
    should_generate = False
    params = {}

    if not any([config_file_found, secret_file_found]):
        should_generate = True
        logger.warning("Unable to find {0} or {1}".format(config_file, secret_file))

        logger.info("Loading parameters from {}".format(generate_file))

        params, err, code = params_from_file(generate_file)
        if code != 0:
            logger.error("Unable to load generate parameters; reason={}".format(err))
            raise click.Abort()

    deps = ["config_conn", "secret_conn"]
    wait_for(manager, deps=deps)

    wrappers = [
        (manager.config, config_file),
        (manager.secret, secret_file),
    ]

    if should_generate:
        logger.info("Generating config and secret.")

        # tolerancy before checking existing key
        time.sleep(5)

        ctx_generator = CtxGenerator(params)
        ctx = ctx_generator.generate()

        for wrapper in wrappers:
            data = ctx[wrapper[0].adapter.type]
            _save_generated_ctx(wrapper[0], wrapper[1], data)
            _dump_to_file(wrapper[0], wrapper[1])
    else:
        for wrapper in wrappers:
            logger.info("Found {}".format(wrapper[1]))
            _load_from_file(wrapper[0], wrapper[1])


@cli.command()
@click.option(
    "--config-file",
    type=click.Path(exists=False),
    help="Absolute path to file to save config",
    default=DEFAULT_CONFIG_FILE,
    show_default=True,
)
@click.option(
    "--secret-file",
    type=click.Path(exists=False),
    help="Absolute path to file to save secret",
    default=DEFAULT_SECRET_FILE,
    show_default=True,
)
def dump(config_file, secret_file):
    """Dumps config and secret into JSON files.
    """
    deps = ["config_conn", "secret_conn"]
    wait_for(manager, deps=deps)

    wrappers = [
        (manager.config, config_file),
        (manager.secret, secret_file),
    ]
    for wrapper in wrappers:
        _dump_to_file(wrapper[0], wrapper[1])


if __name__ == "__main__":
    cli()
