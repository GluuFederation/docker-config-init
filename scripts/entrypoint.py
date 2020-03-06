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


def bytes_as_isostring(val):
    return str(val, "ISO-8859-1")


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


def generate_ctx(params):
    """Generates config and secret contexts.
    """
    admin_pw = params["admin_pw"]
    ldap_pw = params["ldap_pw"]
    email = params["email"]
    hostname = params["hostname"]
    org_name = params["org_name"]
    country_code = params["country_code"]
    state = params["state"]
    city = params["city"]

    ctx = {"config": {}, "secret": {}}

    ctx["secret"]["encoded_salt"] = get_or_set_secret("encoded_salt", get_random_chars(24))

    ctx["config"]["orgName"] = get_or_set_config("orgName", org_name)

    ctx["config"]["country_code"] = get_or_set_config("country_code", country_code)

    ctx["config"]["state"] = get_or_set_config("state", state)

    ctx["config"]["city"] = get_or_set_config("city", city)

    ctx["config"]["hostname"] = get_or_set_config("hostname", hostname)

    ctx["config"]["admin_email"] = get_or_set_config("admin_email", email)

    ctx["config"]["default_openid_jks_dn_name"] = get_or_set_config(
        "default_openid_jks_dn_name", "CN=oxAuth CA Certificates")

    ctx["secret"]["pairwiseCalculationKey"] = get_or_set_secret(
        "pairwiseCalculationKey",
        get_sys_random_chars(random.randint(20, 30)),
    )

    ctx["secret"]["pairwiseCalculationSalt"] = get_or_set_secret(
        "pairwiseCalculationSalt",
        get_sys_random_chars(random.randint(20, 30)),
    )

    ctx["config"]["jetty_base"] = get_or_set_config("jetty_base", "/opt/gluu/jetty")

    ctx["config"]["fido2ConfigFolder"] = get_or_set_config("fido2ConfigFolder", "/etc/gluu/conf/fido2")

    ctx["config"]["admin_inum"] = get_or_set_config("admin_inum", "{}".format(uuid.uuid4()))

    ctx["secret"]["encoded_oxtrust_admin_password"] = get_or_set_secret(
        "encoded_oxtrust_admin_password", ldap_encode(admin_pw))

    # ======
    # OpenDJ
    # ======
    # ctx["secret"]["encoded_ldap_pw"] = get_or_set_secret("encoded_ldap_pw", ldap_encode(admin_pw))

    ctx["secret"]["encoded_ox_ldap_pw"] = get_or_set_secret(
        "encoded_ox_ldap_pw", encode_text(ldap_pw, ctx["secret"]["encoded_salt"]),
    )

    ctx["config"]["ldap_init_host"] = get_or_set_config("ldap_init_host", "localhost")

    ctx["config"]["ldap_init_port"] = int(get_or_set_config("ldap_init_port", 1636))

    ctx["config"]["ldap_port"] = int(get_or_set_config("ldap_port", 1389))

    ctx["config"]["ldaps_port"] = int(get_or_set_config("ldaps_port", 1636))

    ctx["config"]["ldap_binddn"] = get_or_set_config("ldap_binddn", "cn=directory manager")

    ctx["config"]["ldap_site_binddn"] = get_or_set_config("ldap_site_binddn", "cn=directory manager")

    ctx["secret"]["ldap_truststore_pass"] = get_or_set_secret(
        "ldap_truststore_pass", get_random_chars())

    ctx["config"]["ldapTrustStoreFn"] = get_or_set_config("ldapTrustStoreFn", "/etc/certs/opendj.pkcs12")

    generate_ssl_certkey(
        "opendj",
        ctx["secret"]["ldap_truststore_pass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )

    with open("/etc/certs/opendj.pem", "w") as fw:
        with open("/etc/certs/opendj.crt") as fr:
            ldap_ssl_cert = fr.read()

            ctx["secret"]["ldap_ssl_cert"] = get_or_set_secret(
                "ldap_ssl_cert",
                encode_text(ldap_ssl_cert, ctx["secret"]["encoded_salt"]),
            )

        with open("/etc/certs/opendj.key") as fr:
            ldap_ssl_key = fr.read()

            ctx["secret"]["ldap_ssl_key"] = get_or_set_secret(
                "ldap_ssl_key",
                encode_text(ldap_ssl_key, ctx["secret"]["encoded_salt"]),
            )

        ldap_ssl_cacert = "".join([ldap_ssl_cert, ldap_ssl_key])
        fw.write(ldap_ssl_cacert)

        ctx["secret"]["ldap_ssl_cacert"] = get_or_set_secret(
            "ldap_ssl_cacert",
            encode_text(ldap_ssl_cacert, ctx["secret"]["encoded_salt"]),
        )

    generate_pkcs12(
        "opendj",
        ctx["secret"]["ldap_truststore_pass"],
        ctx["config"]["hostname"],
    )
    with open(ctx["config"]["ldapTrustStoreFn"], "rb") as fr:
        ctx["secret"]["ldap_pkcs12_base64"] = get_or_set_secret(
            "ldap_pkcs12_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"]),
        )

    ctx["secret"]["encoded_ldapTrustStorePass"] = get_or_set_secret(
        "encoded_ldapTrustStorePass",
        encode_text(ctx["secret"]["ldap_truststore_pass"], ctx["secret"]["encoded_salt"]),
    )

    # ======
    # oxAuth
    # ======
    ctx["config"]["oxauth_client_id"] = get_or_set_config(
        "oxauth_client_id",
        "1001.{}".format(uuid.uuid4()),
    )

    ctx["secret"]["oxauthClient_encoded_pw"] = get_or_set_secret(
        "oxauthClient_encoded_pw",
        encode_text(get_random_chars(), ctx["secret"]["encoded_salt"]),
    )

    ctx["config"]["oxauth_openid_jks_fn"] = get_or_set_config(
        "oxauth_openid_jks_fn", "/etc/certs/oxauth-keys.jks")

    ctx["secret"]["oxauth_openid_jks_pass"] = get_or_set_secret(
        "oxauth_openid_jks_pass", get_random_chars())

    ctx["config"]["oxauth_openid_jwks_fn"] = get_or_set_config(
        "oxauth_openid_jwks_fn", "/etc/certs/oxauth-keys.json")

    ctx["config"]["oxauth_legacyIdTokenClaims"] = get_or_set_config(
        "oxauth_legacyIdTokenClaims", "true")

    ctx["config"]["oxauth_openidScopeBackwardCompatibility"] = get_or_set_config(
        "oxauth_openidScopeBackwardCompatibility", "true")

    _, err, retcode = generate_openid_keys(
        ctx["secret"]["oxauth_openid_jks_pass"],
        ctx["config"]["oxauth_openid_jks_fn"],
        ctx["config"]["oxauth_openid_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
        exp=2,
    )
    if retcode != 0:
        logger.error("Unable to generate oxAuth keys; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["oxauth_openid_jwks_fn"])
    ctx["secret"]["oxauth_openid_key_base64"] = get_or_set_secret(
        "oxauth_openid_key_base64",
        encode_template(fn, ctx, basedir),
    )

    # oxAuth keys
    ctx["config"]["oxauth_key_rotated_at"] = int(get_or_set_config(
        "oxauth_key_rotated_at",
        int(time.time()),
    ))

    with open(ctx["config"]["oxauth_openid_jks_fn"], "rb") as fr:
        ctx["secret"]["oxauth_jks_base64"] = get_or_set_secret(
            "oxauth_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"])
        )

    # =======
    # SCIM RS
    # =======
    ctx["config"]["scim_rs_client_id"] = get_or_set_config(
        "scim_rs_client_id",
        "1201.{}".format(uuid.uuid4()),
    )

    ctx["config"]["scim_rs_client_jks_fn"] = get_or_set_config(
        "scim_rs_client_jks_fn", "/etc/certs/scim-rs.jks")

    ctx["config"]["scim_rs_client_jwks_fn"] = get_or_set_config(
        "scim_rs_client_jwks_fn", "/etc/certs/scim-rs-keys.json")

    ctx["secret"]["scim_rs_client_jks_pass"] = get_or_set_secret(
        "scim_rs_client_jks_pass", get_random_chars())

    ctx["secret"]["scim_rs_client_jks_pass_encoded"] = get_or_set_secret(
        "scim_rs_client_jks_pass_encoded",
        encode_text(ctx["secret"]["scim_rs_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    _, err, retcode = generate_openid_keys(
        ctx["secret"]["scim_rs_client_jks_pass"],
        ctx["config"]["scim_rs_client_jks_fn"],
        ctx["config"]["scim_rs_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate SCIM RS keys; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["scim_rs_client_jwks_fn"])
    ctx["secret"]["scim_rs_client_base64_jwks"] = get_or_set_secret(
        "scim_rs_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["scim_rs_client_jks_fn"], "rb") as fr:
        ctx["secret"]["scim_rs_jks_base64"] = get_or_set_secret(
            "scim_rs_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"]),
        )

    # =======
    # SCIM RP
    # =======
    ctx["config"]["scim_rp_client_id"] = get_or_set_config(
        "scim_rp_client_id",
        "1202.{}".format(uuid.uuid4()),
    )

    ctx["config"]["scim_rp_client_jks_fn"] = get_or_set_config(
        "scim_rp_client_jks_fn", "/etc/certs/scim-rp.jks")

    ctx["config"]["scim_rp_client_jwks_fn"] = get_or_set_config(
        "scim_rp_client_jwks_fn", "/etc/certs/scim-rp-keys.json")

    ctx["secret"]["scim_rp_client_jks_pass"] = get_or_set_secret(
        "scim_rp_client_jks_pass", get_random_chars())

    ctx["secret"]["scim_rp_client_jks_pass_encoded"] = get_or_set_secret(
        "scim_rp_client_jks_pass_encoded",
        encode_text(ctx["secret"]["scim_rp_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    _, err, retcode = generate_openid_keys(
        ctx["secret"]["scim_rp_client_jks_pass"],
        ctx["config"]["scim_rp_client_jks_fn"],
        ctx["config"]["scim_rp_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate SCIM RP keys; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["scim_rp_client_jwks_fn"])
    ctx["secret"]["scim_rp_client_base64_jwks"] = get_or_set_secret(
        "scim_rp_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["scim_rp_client_jks_fn"], "rb") as fr:
        ctx["secret"]["scim_rp_jks_base64"] = get_or_set_secret(
            "scim_rp_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"]),
        )

    ctx["config"]["scim_resource_oxid"] = get_or_set_config(
        "scim_resource_oxid",
        "1203.{}".format(uuid.uuid4()),
    )

    # ===========
    # Passport RS
    # ===========
    ctx["config"]["passport_rs_client_id"] = get_or_set_config(
        "passport_rs_client_id",
        "1501.{}".format(uuid.uuid4()),
    )

    ctx["config"]["passport_rs_client_jks_fn"] = get_or_set_config(
        "passport_rs_client_jks_fn", "/etc/certs/passport-rs.jks")

    ctx["config"]["passport_rs_client_jwks_fn"] = get_or_set_config(
        "passport_rs_client_jwks_fn", "/etc/certs/passport-rs-keys.json")

    ctx["secret"]["passport_rs_client_jks_pass"] = get_or_set_secret(
        "passport_rs_client_jks_pass", get_random_chars())

    ctx["secret"]["passport_rs_client_jks_pass_encoded"] = get_or_set_secret(
        "passport_rs_client_jks_pass_encoded",
        encode_text(ctx["secret"]["passport_rs_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    out, err, retcode = generate_openid_keys(
        ctx["secret"]["passport_rs_client_jks_pass"],
        ctx["config"]["passport_rs_client_jks_fn"],
        ctx["config"]["passport_rs_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate Passport RS keys; reason={}".format(err))
        click.Abort()

    ctx["config"]["passport_rs_client_cert_alg"] = get_or_set_config(
        "passport_rs_client_cert_alg", "RS512")

    cert_alias = ""
    for key in json.loads(out)["keys"]:
        if key["alg"] == ctx["config"]["passport_rs_client_cert_alg"]:
            cert_alias = key["kid"]
            break

    basedir, fn = os.path.split(ctx["config"]["passport_rs_client_jwks_fn"])
    ctx["secret"]["passport_rs_client_base64_jwks"] = get_or_set_secret(
        "passport_rs_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["passport_rs_client_jks_fn"], "rb") as fr:
        ctx["secret"]["passport_rs_jks_base64"] = get_or_set_secret(
            "passport_rs_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"])
        )

    ctx["config"]["passport_resource_id"] = get_or_set_config(
        "passport_resource_id",
        '1504.{}'.format(uuid.uuid4()),
    )

    ctx["config"]["passport_rs_client_cert_alias"] = get_or_set_config(
        "passport_rs_client_cert_alias", cert_alias
    )

    # ===========
    # Passport RP
    # ===========
    ctx["config"]["passport_rp_client_id"] = get_or_set_config(
        "passport_rp_client_id",
        "1502.{}".format(uuid.uuid4()),
    )

    ctx["config"]["passport_rp_ii_client_id"] = get_or_set_config(
        "passport_rp_ii_client_id",
        "1503.{}".format(uuid.uuid4()),
    )

    ctx["secret"]["passport_rp_client_jks_pass"] = get_or_set_secret(
        "passport_rp_client_jks_pass", get_random_chars())

    ctx["config"]["passport_rp_client_jks_fn"] = get_or_set_config(
        "passport_rp_client_jks_fn", "/etc/certs/passport-rp.jks")

    ctx["config"]["passport_rp_client_jwks_fn"] = get_or_set_config(
        "passport_rp_client_jwks_fn", "/etc/certs/passport-rp-keys.json")

    ctx["config"]["passport_rp_client_cert_fn"] = get_or_set_config(
        "passport_rp_client_cert_fn", "/etc/certs/passport-rp.pem")

    ctx["config"]["passport_rp_client_cert_alg"] = get_or_set_config(
        "passport_rp_client_cert_alg", "RS512")

    out, err, code = generate_openid_keys(
        ctx["secret"]["passport_rp_client_jks_pass"],
        ctx["config"]["passport_rp_client_jks_fn"],
        ctx["config"]["passport_rp_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate Passport RP keys; reason={}".format(err))
        click.Abort()

    cert_alias = ""
    for key in json.loads(out)["keys"]:
        if key["alg"] == ctx["config"]["passport_rp_client_cert_alg"]:
            cert_alias = key["kid"]
            break

    _, err, retcode = export_openid_keys(
        ctx["config"]["passport_rp_client_jks_fn"],
        ctx["secret"]["passport_rp_client_jks_pass"],
        cert_alias,
        ctx["config"]["passport_rp_client_cert_fn"],
    )
    if retcode != 0:
        logger.error("Unable to generate Passport RP client cert; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["passport_rp_client_jwks_fn"])
    ctx["secret"]["passport_rp_client_base64_jwks"] = get_or_set_secret(
        "passport_rp_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    ctx["config"]["passport_rp_client_cert_alias"] = get_or_set_config(
        "passport_rp_client_cert_alias", cert_alias
    )

    with open(ctx["config"]["passport_rp_client_jks_fn"], "rb") as fr:
        ctx["secret"]["passport_rp_jks_base64"] = get_or_set_secret(
            "passport_rp_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"]),
        )

    with open(ctx["config"]["passport_rp_client_cert_fn"]) as fr:
        ctx["secret"]["passport_rp_client_cert_base64"] = get_or_set_secret(
            "passport_rp_client_cert_base64",
            encode_text(fr.read(), ctx["secret"]["encoded_salt"]),
        )

    # ===========
    # Passport SP
    # ===========

    ctx["secret"]["passportSpKeyPass"] = get_or_set_secret("passportSpKeyPass", get_random_chars())

    ctx["config"]["passportSpTLSCACert"] = get_or_set_config("passportSpTLSCACert", '/etc/certs/passport-sp.pem')

    ctx["config"]["passportSpTLSCert"] = get_or_set_config("passportSpTLSCert", '/etc/certs/passport-sp.crt')

    ctx["config"]["passportSpTLSKey"] = get_or_set_config("passportSpTLSKey", '/etc/certs/passport-sp.key')

    ctx["secret"]["passportSpJksPass"] = get_or_set_secret("passportSpJksPass", get_random_chars())

    ctx["config"]["passportSpJksFn"] = get_or_set_config("passportSpJksFn", '/etc/certs/passport-sp.jks')

    generate_ssl_certkey(
        "passport-sp",
        ctx["secret"]["passportSpKeyPass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )
    with open(ctx["config"]["passportSpTLSCert"]) as f:
        ctx["secret"]["passport_sp_cert_base64"] = get_or_set_secret(
            "passport_sp_cert_base64",
            encode_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open(ctx["config"]["passportSpTLSKey"]) as f:
        ctx["secret"]["passport_sp_key_base64"] = get_or_set_secret(
            "passport_sp_key_base64",
            encode_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    # ================
    # SSL cert and key
    # ================
    ssl_cert = "/etc/certs/gluu_https.crt"
    ssl_key = "/etc/certs/gluu_https.key"
    ctx["secret"]["ssl_cert_pass"] = get_or_set_secret("ssl_cert_pass", get_random_chars())

    # generate self-signed SSL cert and key only if they aren't exist
    if not(os.path.exists(ssl_cert) and os.path.exists(ssl_key)):
        generate_ssl_certkey(
            "gluu_https",
            ctx["secret"]["ssl_cert_pass"],
            ctx["config"]["admin_email"],
            ctx["config"]["hostname"],
            ctx["config"]["orgName"],
            ctx["config"]["country_code"],
            ctx["config"]["state"],
            ctx["config"]["city"],
        )

    with open(ssl_cert) as f:
        ctx["secret"]["ssl_cert"] = get_or_set_secret("ssl_cert", f.read())

    with open(ssl_key) as f:
        ctx["secret"]["ssl_key"] = get_or_set_secret("ssl_key", f.read())

    # ===================
    # IDP3 (oxShibboleth)
    # ===================
    ctx["config"]["idp_client_id"] = get_or_set_config(
        "idp_client_id",
        "1101.{}".format(uuid.uuid4()),
    )

    ctx["secret"]["idpClient_encoded_pw"] = get_or_set_secret(
        "idpClient_encoded_pw",
        encode_text(get_random_chars(), ctx["secret"]["encoded_salt"]),
    )

    ctx["config"]["shibJksFn"] = get_or_set_config("shibJksFn", "/etc/certs/shibIDP.jks")

    ctx["secret"]["shibJksPass"] = get_or_set_secret("shibJksPass", get_random_chars())

    ctx["secret"]["encoded_shib_jks_pw"] = get_or_set_secret(
        "encoded_shib_jks_pw",
        encode_text(ctx["secret"]["shibJksPass"], ctx["secret"]["encoded_salt"])
    )

    generate_ssl_certkey(
        "shibIDP",
        ctx["secret"]["shibJksPass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )

    generate_keystore("shibIDP", ctx["config"]["hostname"], ctx["secret"]["shibJksPass"])

    with open("/etc/certs/shibIDP.crt") as f:
        ctx["secret"]["shibIDP_cert"] = get_or_set_secret(
            "shibIDP_cert",
            encode_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open("/etc/certs/shibIDP.key") as f:
        ctx["secret"]["shibIDP_key"] = get_or_set_secret(
            "shibIDP_key",
            encode_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open(ctx["config"]["shibJksFn"], "rb") as f:
        ctx["secret"]["shibIDP_jks_base64"] = get_or_set_secret(
            "shibIDP_jks_base64",
            encode_text(bytes_as_isostring(f.read()), ctx["secret"]["encoded_salt"])
        )

    ctx["config"]["shibboleth_version"] = get_or_set_config("shibboleth_version", "v3")

    ctx["config"]["idp3Folder"] = get_or_set_config("idp3Folder", "/opt/shibboleth-idp")

    idp3_signing_cert = "/etc/certs/idp-signing.crt"

    idp3_signing_key = "/etc/certs/idp-signing.key"

    generate_ssl_certkey(
        "idp-signing",
        ctx["secret"]["shibJksPass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )

    with open(idp3_signing_cert) as f:
        ctx["secret"]["idp3SigningCertificateText"] = get_or_set_secret(
            "idp3SigningCertificateText", f.read())

    with open(idp3_signing_key) as f:
        ctx["secret"]["idp3SigningKeyText"] = get_or_set_secret(
            "idp3SigningKeyText", f.read())

    idp3_encryption_cert = "/etc/certs/idp-encryption.crt"

    idp3_encryption_key = "/etc/certs/idp-encryption.key"

    generate_ssl_certkey(
        "idp-encryption",
        ctx["secret"]["shibJksPass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )

    with open(idp3_encryption_cert) as f:
        ctx["secret"]["idp3EncryptionCertificateText"] = get_or_set_secret(
            "idp3EncryptionCertificateText", f.read())

    with open(idp3_encryption_key) as f:
        ctx["secret"]["idp3EncryptionKeyText"] = get_or_set_secret(
            "idp3EncryptionKeyText", f.read())

    # gen_idp3_key(ctx["secret"]["shibJksPass"])

    # with open("/etc/certs/sealer.jks") as f:
    #     ctx["secret"]["sealer_jks_base64"] = get_or_set_secret(
    #         "sealer_jks_base64",
    #         encode_text(f.read(), ctx["secret"]["encoded_salt"])
    #     )

    # ==============
    # oxTrust API RS
    # ==============
    ctx["config"]["api_rs_client_jks_fn"] = get_or_set_config(
        "api_rs_client_jks_fn", "/etc/certs/api-rs.jks")

    ctx["config"]["api_rs_client_jwks_fn"] = get_or_set_config(
        "api_rs_client_jwks_fn", "/etc/certs/api-rs-keys.json")

    ctx["secret"]["api_rs_client_jks_pass"] = get_or_set_secret(
        "api_rs_client_jks_pass", get_random_chars(),
    )
    ctx["secret"]["api_rs_client_jks_pass_encoded"] = get_or_set_secret(
        "api_rs_client_jks_pass_encoded",
        encode_text(ctx["secret"]["api_rs_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    _, err, retcode = generate_openid_keys(
        ctx["secret"]["api_rs_client_jks_pass"],
        ctx["config"]["api_rs_client_jks_fn"],
        ctx["config"]["api_rs_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate oxTrust API RS keys; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["api_rs_client_jwks_fn"])
    ctx["secret"]["api_rs_client_base64_jwks"] = get_or_set_secret(
        "api_rs_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )
    ctx["config"]["oxtrust_resource_server_client_id"] = get_or_set_config(
        "oxtrust_resource_server_client_id",
        '1401.{}'.format(uuid.uuid4()),
    )
    ctx["config"]["oxtrust_resource_id"] = get_or_set_config(
        "oxtrust_resource_id",
        '1403.{}'.format(uuid.uuid4()),
    )
    with open(ctx["config"]["api_rs_client_jks_fn"], "rb") as fr:
        ctx["secret"]["api_rs_jks_base64"] = get_or_set_secret(
            "api_rs_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"])
        )

    # ==============
    # oxTrust API RP
    # ==============
    ctx["config"]["api_rp_client_jks_fn"] = get_or_set_config(
        "api_rp_client_jks_fn", "/etc/certs/api-rp.jks")

    ctx["config"]["api_rp_client_jwks_fn"] = get_or_set_config(
        "api_rp_client_jwks_fn", "/etc/certs/api-rp-keys.json")

    ctx["secret"]["api_rp_client_jks_pass"] = get_or_set_secret(
        "api_rp_client_jks_pass", get_random_chars(),
    )
    ctx["secret"]["api_rp_client_jks_pass_encoded"] = get_or_set_secret(
        "api_rp_client_jks_pass_encoded",
        encode_text(ctx["secret"]["api_rp_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )
    _, err, retcode = generate_openid_keys(
        ctx["secret"]["api_rp_client_jks_pass"],
        ctx["config"]["api_rp_client_jks_fn"],
        ctx["config"]["api_rp_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate oxTrust API RP keys; reason={}".format(err))
        click.Abort()

    basedir, fn = os.path.split(ctx["config"]["api_rp_client_jwks_fn"])
    ctx["secret"]["api_rp_client_base64_jwks"] = get_or_set_secret(
        "api_rp_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    ctx["config"]["oxtrust_requesting_party_client_id"] = get_or_set_config(
        "oxtrust_requesting_party_client_id",
        '1402.{}'.format(uuid.uuid4()),
    )

    with open(ctx["config"]["api_rp_client_jks_fn"], "rb") as fr:
        ctx["secret"]["api_rp_jks_base64"] = get_or_set_secret(
            "api_rp_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"])
        )

    # =======================
    # oxTrust API test client
    # =======================
    ctx["config"]["api_test_client_id"] = get_or_set_config(
        "api_test_client_id",
        "0008-{}".format(uuid.uuid4()),
    )
    ctx["secret"]["api_test_client_secret"] = get_or_set_secret(
        "api_test_client_secret",
        get_random_chars(24),
    )

    # ======
    # Radius
    # ======
    ctx["config"]["gluu_radius_client_id"] = get_or_set_config(
        "gluu_radius_client_id",
        '1701.{}'.format(uuid.uuid4()),
    )
    # ctx["config"]["ox_radius_client_id"] = get_or_set_config(
    #     "ox_radius_client_id",
    #     '0008-{}'.format(uuid.uuid4()),
    # )
    ctx["secret"]["gluu_ro_encoded_pw"] = get_or_set_secret(
        "gluu_ro_encoded_pw",
        encode_text(get_random_chars(), ctx["secret"]["encoded_salt"]),
    )

    radius_jwt_pass = get_random_chars()
    ctx["secret"]["radius_jwt_pass"] = get_or_set_secret(
        "radius_jwt_pass",
        encode_text(radius_jwt_pass, ctx["secret"]["encoded_salt"]),
    )

    out, err, code = generate_openid_keys(
        radius_jwt_pass,
        "/etc/certs/gluu-radius.jks",
        "/etc/certs/gluu-radius.keys",
        ctx["config"]["default_openid_jks_dn_name"],
    )
    if retcode != 0:
        logger.error("Unable to generate Gluu Radius keys; reason={}".format(err))
        click.Abort()

    for key in json.loads(out)["keys"]:
        if key["alg"] == "RS512":
            ctx["config"]["radius_jwt_keyId"] = key["kid"]
            break

    with open("/etc/certs/gluu-radius.jks", "rb") as fr:
        ctx["secret"]["radius_jks_base64"] = get_or_set_secret(
            "radius_jks_base64",
            encode_text(bytes_as_isostring(fr.read()), ctx["secret"]["encoded_salt"])
        )

    basedir, fn = os.path.split("/etc/certs/gluu-radius.keys")
    ctx["secret"]["gluu_ro_client_base64_jwks"] = get_or_set_secret(
        "gluu_ro_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    # ================
    # SCIM test client
    # ================
    ctx["config"]["scim_test_client_id"] = get_or_set_config(
        "scim_test_client_id",
        "0008-{}".format(uuid.uuid4()),
    )
    ctx["secret"]["scim_test_client_secret"] = get_or_set_secret(
        "scim_test_client_secret",
        get_random_chars(24),
    )

    # =========
    # Couchbase
    # =========

    ctx["config"]["couchbaseTrustStoreFn"] = get_or_set_config(
        "couchbaseTrustStoreFn", "/etc/certs/couchbase.pkcs12",
    )

    ctx["secret"]["couchbase_shib_user_password"] = get_random_chars()

    # populated config
    return ctx


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


# def gen_idp3_key(shibJksPass):
#     out, err, retcode = exec_cmd("java -classpath /app/javalibs/idp3_cml_keygenerator.jar "
#                                  "'org.gluu.oxshibboleth.keygenerator.KeyGenerator' "
#                                  "/etc/certs {}".format(shibJksPass))
#     return out, err, retcode


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

    logger.info("Saving {} to {}.".format(ctx_manager.adapter.type, filepath))
    data = {"_{}".format(ctx_manager.adapter.type): data}
    data = json.dumps(data, indent=4)

    with open(filepath, "w") as f:
        f.write(data)


def _load_from_file(ctx_manager, filepath):
    logger.info("Loading {} from {}.".format(
        ctx_manager.adapter.type, filepath))

    with open(filepath, "r") as f:
        data = json.loads(f.read())

    if "_{}".format(ctx_manager.adapter.type) not in data:
        logger.warn("Missing '_{}' key.".format(ctx_manager.adapter.type))
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
    data = json.dumps(data, indent=4)
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
        logger.warn("Unable to find {0} or {1}".format(config_file, secret_file))

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

        ctx = generate_ctx(params)

        for wrapper in wrappers:
            data = ctx[wrapper[0].adapter.type]
            _save_generated_ctx(wrapper[0], wrapper[1], data)
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


@cli.command()
@click.option("--overwrite", default=False, help="Overwrite secret keys.", is_flag=True)
@click.option("--prune", default=False, help="Prune migrated keys.", is_flag=True)
def migrate(overwrite, prune):
    """Migrates keys from config to secret backend.
    """
    SECRET_KEYS = (
        'encoded_salt',
        'pairwiseCalculationKey',
        'pairwiseCalculationSalt',
        'ldap_truststore_pass',
        'ldap_ssl_cert',
        'ldap_ssl_key',
        'ldap_ssl_cacert',
        'ldap_pkcs12_base64',
        'encoded_ldapTrustStorePass',
        'encoded_ldap_pw',
        'encoded_ox_ldap_pw',
        'encoded_replication_pw',
        'encoded_ox_replication_pw',
        'oxauthClient_encoded_pw',
        'oxauth_openid_jks_pass',
        'oxauth_openid_key_base64',
        'scim_rs_client_jks_pass',
        'scim_rs_client_jks_pass_encoded',
        'scim_rs_client_base64_jwks',
        'scim_rs_jks_base64',
        'scim_rp_client_jks_pass',
        'scim_rp_client_jks_pass_encoded',
        'scim_rp_client_base64_jwks',
        'scim_rp_jks_base64',
        'passport_rs_client_jks_pass',
        'passport_rs_client_jks_pass_encoded',
        'passport_rs_client_base64_jwks',
        'passport_rs_jks_base64',
        'passport_rp_client_jks_pass',
        'passport_rp_client_base64_jwks',
        'passport_rp_jks_base64',
        'passport_rp_client_cert_base64',
        'passportSpKeyPass',
        'passportSpJksPass',
        'passport_sp_cert_base64',
        'passport_sp_key_base64',
        'ssl_cert',
        'ssl_key',
        'idpClient_encoded_pw',
        'shibJksPass',
        'encoded_shib_jks_pw',
        'shibIDP_cert',
        'shibIDP_key',
        'shibIDP_jks_base64',
        'idp3SigningCertificateText',
        'idp3SigningKeyText',
        'idp3EncryptionCertificateText',
        'idp3EncryptionKeyText',
        'sealer_jks_base64',
        "oxauth_jks_base64",
    )

    deps = ["config_conn", "secret_conn"]
    wait_for(manager, deps=deps)

    if overwrite:
        logger.warn("overwrite mode is enabled")

    if prune:
        logger.warn("prune mode is enabled")

    for k, v in manager.config.all().items():
        if k not in SECRET_KEYS or not v:
            continue

        # if key must be overwritten or not available in secret backend,
        # then migrate it; note that to check whether key is actually
        # in secret backend, we need to use low-level API
        # (using `secret.adapter.get` instead of `secret.get`)
        if overwrite or not manager.secret.adapter.get(k):
            logger.info("migrating {} from config to secret backend".format(k))
            manager.secret.set(k, v)

        # if key must be removed from config, then delete it
        # (only if it has been migrated)
        if prune and manager.secret.adapter.get(k):
            logger.info("deleting {} from config".format(k))
            manager.config.delete(k)


if __name__ == "__main__":
    cli()
