import base64
import hashlib
import json
import os
import random
import re
import shlex
import string
import subprocess
import time
import uuid
# from collections import namedtuple
from functools import partial

import click
import pyDes

from gluulib import get_manager
from wait_for import wait_for


# Default charset
_DEFAULT_CHARS = "".join([string.ascii_uppercase,
                          string.digits,
                          string.lowercase])

CTX_CONFIG = "config"
CTX_SECRET = "secret"
CONFIG_FILEPATH = "/opt/config-init/db/config.json"
SECRET_FILEPATH = "/opt/config-init/db/secret.json"

manager = get_manager()


def get_random_chars(size=12, chars=_DEFAULT_CHARS):
    """Generates random characters.
    """
    return ''.join(random.choice(chars) for _ in range(size))


def ldap_encode(password):
    # borrowed from community-edition-setup project
    # see http://git.io/vIRex
    salt = os.urandom(4)
    sha = hashlib.sha1(password)
    sha.update(salt)
    b64encoded = '{0}{1}'.format(sha.digest(), salt).encode('base64').strip()
    encrypted_password = '{{SSHA}}{0}'.format(b64encoded)
    return encrypted_password


def get_quad():
    # borrowed from community-edition-setup project
    # see http://git.io/he1p
    return str(uuid.uuid4())[:4].upper()


def encrypt_text(text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = cipher.encrypt(b"{}".format(text))
    return base64.b64encode(encrypted_text)


def reindent(text, num_spaces=1):
    text = [(num_spaces * " ") + line.lstrip() for line in text.splitlines()]
    text = "\n".join(text)
    return text


def safe_render(text, ctx):
    text = re.sub(r"%([^\(])", r"%%\1", text)
    # There was a % at the end?
    text = re.sub(r"%$", r"%%", text)
    return text % ctx


def generate_base64_contents(text, num_spaces=1):
    text = text.encode("base64").strip()
    if num_spaces > 0:
        text = reindent(text, num_spaces)
    return text


def get_sys_random_chars(size=12, chars=_DEFAULT_CHARS):
    """Generates random characters based on OS.
    """
    return ''.join(random.SystemRandom().choice(chars) for _ in range(size))


def join_quad_str(x):
    return ".".join([get_quad() for _ in xrange(x)])


def safe_inum_str(x):
    return x.replace("@", "").replace("!", "").replace(".", "")


def encode_template(fn, ctx, base_dir="/opt/config-init/templates"):
    path = os.path.join(base_dir, fn)
    # ctx is nested which has `config` and `secret` keys
    data = {}
    for _, v in ctx.iteritems():
        data.update(v)
    with open(path) as f:
        return generate_base64_contents(safe_render(f.read(), data))


def exec_cmd(cmd):
    args = shlex.split(cmd)
    popen = subprocess.Popen(args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    retcode = popen.returncode
    return stdout, stderr, retcode


def generate_openid_keys(passwd, jks_path, jwks_path, dn, exp=365,
                         alg="RS256 RS384 RS512 ES256 ES384 ES512"):
    if os.path.exists(jks_path):
        os.unlink(jks_path)

    if os.path.exists(jwks_path):
        os.unlink(jwks_path)

    cmd = " ".join([
        "java",
        "-jar", "/opt/config-init/javalibs/oxauth-client.jar",
        "-enc_keys", alg,
        "-sig_keys", alg,
        "-dnname", "{!r}".format(dn),
        "-expiration", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])
    out, err, retcode = exec_cmd(cmd)
    if retcode == 0:
        with open(jwks_path, "w") as f:
            f.write(out)
    return out


def export_openid_keys(keystore, keypasswd, alias, export_file):
    cmd = " ".join([
        "java",
        "-cp /opt/config-init/javalibs/oxauth-client.jar",
        "org.xdi.oxauth.util.KeyExporter",
        "-keystore {}".format(keystore),
        "-keypasswd '{}'".format(keypasswd),
        "-alias '{}'".format(alias),
        "-exportfile {}".format(export_file),
    ])
    return exec_cmd(cmd)


def encode_keys_template(jks_pass, jks_fn, jwks_fn, ctx):
    base_dir, fn = os.path.split(jwks_fn)
    return encode_template(fn, ctx, base_dir=base_dir)


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


def generate_ctx(admin_pw, email, domain, org_name, country_code, state,
                 city, ldap_type="opendj", base_inum="", inum_org="",
                 inum_appliance=""):
    """Generates config and secret contexts.
    """
    ctx = {"config": {}, "secret": {}}

    ctx["secret"]["encoded_salt"] = get_or_set_secret("encoded_salt", get_random_chars(24))
    ctx["config"]["orgName"] = get_or_set_config("orgName", org_name)
    ctx["config"]["country_code"] = get_or_set_config("country_code", country_code)
    ctx["config"]["state"] = get_or_set_config("state", state)
    ctx["config"]["city"] = get_or_set_config("city", city)
    ctx["config"]["hostname"] = get_or_set_config("hostname", domain)
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

    # ====
    # LDAP
    # ====
    ctx["config"]["ldap_init_host"] = get_or_set_config("ldap_init_host", "localhost")
    ctx["config"]["ldap_init_port"] = int(get_or_set_config("ldap_init_port", 1636))
    ctx["config"]["ldap_port"] = int(get_or_set_config("ldap_port", 1389))
    ctx["config"]["ldaps_port"] = int(get_or_set_config("ldaps_port", 1636))

    ctx["secret"]["ldap_truststore_pass"] = get_or_set_secret(
        "ldap_truststore_pass", get_random_chars())

    ctx["config"]["ldap_type"] = get_or_set_config("ldap_type", ldap_type)

    if ctx["config"]["ldap_type"] == "opendj":
        ldap_binddn = "cn=directory manager"
        ldap_site_binddn = "cn=directory manager"
        ldapTrustStoreFn = "/etc/certs/opendj.pkcs12"
    else:
        ldap_binddn = "cn=directory manager,o=gluu"
        ldap_site_binddn = "cn=directory manager,o=site"
        ldapTrustStoreFn = "/etc/certs/openldap.pkcs12"

    ctx["secret"]["ldap_binddn"] = get_or_set_secret("ldap_binddn", ldap_binddn)
    ctx["config"]["ldap_site_binddn"] = get_or_set_config("ldap_site_binddn", ldap_site_binddn)
    ctx["config"]["ldapTrustStoreFn"] = get_or_set_config("ldapTrustStoreFn", ldapTrustStoreFn)

    generate_ssl_certkey(
        ctx["config"]["ldap_type"],
        ctx["secret"]["ldap_truststore_pass"],
        ctx["config"]["admin_email"],
        ctx["config"]["hostname"],
        ctx["config"]["orgName"],
        ctx["config"]["country_code"],
        ctx["config"]["state"],
        ctx["config"]["city"],
    )

    with open("/etc/certs/{}.crt".format(ctx["config"]["ldap_type"])) as fr:
        ldap_ssl_cert = fr.read()

        ctx["secret"]["ldap_ssl_cert"] = get_or_set_secret(
            "ldap_ssl_cert",
            encrypt_text(ldap_ssl_cert, ctx["secret"]["encoded_salt"]),
        )

    with open("/etc/certs/{}.key".format(ctx["config"]["ldap_type"])) as fr:
        ldap_ssl_key = fr.read()

        ctx["secret"]["ldap_ssl_key"] = get_or_set_secret(
            "ldap_ssl_key",
            encrypt_text(ldap_ssl_key, ctx["secret"]["encoded_salt"]),
        )

    with open("/etc/certs/{}.pem".format(ctx["config"]["ldap_type"]), "w") as fw:
        ldap_ssl_cacert = "".join([ldap_ssl_cert, ldap_ssl_key])
        fw.write(ldap_ssl_cacert)

        ctx["secret"]["ldap_ssl_cacert"] = get_or_set_secret(
            "ldap_ssl_cacert",
            encrypt_text(ldap_ssl_cacert, ctx["secret"]["encoded_salt"]),
        )

    generate_pkcs12(
        ctx["config"]["ldap_type"],
        ctx["secret"]["ldap_truststore_pass"],
        ctx["config"]["hostname"],
    )
    with open(ctx["config"]["ldapTrustStoreFn"], "rb") as fr:
        ctx["secret"]["ldap_pkcs12_base64"] = get_or_set_secret(
            "ldap_pkcs12_base64",
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"]),
        )

    ctx["secret"]["encoded_ldapTrustStorePass"] = get_or_set_secret(
        "encoded_ldapTrustStorePass",
        encrypt_text(ctx["secret"]["ldap_truststore_pass"], ctx["secret"]["encoded_salt"]),
    )

    ctx["secret"]["encoded_ldap_pw"] = get_or_set_secret("encoded_ldap_pw", ldap_encode(admin_pw))

    ctx["secret"]["encoded_ox_ldap_pw"] = get_or_set_secret(
        "encoded_ox_ldap_pw", encrypt_text(admin_pw, ctx["secret"]["encoded_salt"]),
    )

    ctx["config"]["ldap_use_ssl"] = as_boolean(get_or_set_config("ldap_use_ssl", True))

    ctx["config"]["replication_cn"] = get_or_set_config("replication_cn", "replicator")

    ctx["config"]["replication_dn"] = get_or_set_config(
        "replication_dn", "cn={},o=gluu".format(ctx["config"]["replication_cn"]))

    ctx["secret"]["encoded_replication_pw"] = get_or_set_secret(
        "encoded_replication_pw", ctx["secret"]["encoded_ldap_pw"])

    ctx["secret"]["encoded_ox_replication_pw"] = get_or_set_secret(
        "encoded_ox_replication_pw", ctx["secret"]["encoded_ox_ldap_pw"])

    # ====
    # Inum
    # ====
    ctx["config"]["baseInum"] = get_or_set_config(
        "baseInum",
        base_inum or "@!{}".format(join_quad_str(4))
    )

    ctx["config"]["inumOrg"] = get_or_set_config(
        "inumOrg",
        inum_org or "{}!0001!{}".format(ctx["config"]["baseInum"], join_quad_str(2)),
    )

    ctx["config"]["inumOrgFN"] = get_or_set_config("inumOrgFN", safe_inum_str(ctx["config"]["inumOrg"]))

    ctx["config"]["inumAppliance"] = get_or_set_config(
        "inumAppliance",
        inum_appliance or "{}!0002!{}".format(ctx["config"]["baseInum"], join_quad_str(2)),
    )

    ctx["config"]["inumApplianceFN"] = get_or_set_config(
        "inumApplianceFN", safe_inum_str(ctx["config"]["inumAppliance"]))

    # ======
    # oxAuth
    # ======
    ctx["config"]["oxauth_client_id"] = get_or_set_config(
        "oxauth_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
    )

    ctx["secret"]["oxauthClient_encoded_pw"] = get_or_set_secret(
        "oxauthClient_encoded_pw",
        encrypt_text(get_random_chars(), ctx["secret"]["encoded_salt"]),
    )

    ctx["config"]["oxauth_openid_jks_fn"] = get_or_set_config(
        "oxauth_openid_jks_fn", "/etc/certs/oxauth-keys.jks")

    ctx["secret"]["oxauth_openid_jks_pass"] = get_or_set_secret(
        "oxauth_openid_jks_pass", get_random_chars())

    ctx["config"]["oxauth_openid_jwks_fn"] = get_or_set_config(
        "oxauth_openid_jwks_fn", "/etc/certs/oxauth-keys.json")

    ctx["secret"]["oxauth_config_base64"] = get_or_set_secret(
        "oxauth_config_base64",
        encode_template("oxauth-config.json", ctx),
    )

    ctx["config"]["oxauth_static_conf_base64"] = get_or_set_config(
        "oxauth_static_conf_base64",
        encode_template("oxauth-static-conf.json", ctx),
    )

    ctx["config"]["oxauth_error_base64"] = get_or_set_config(
        "oxauth_error_base64",
        encode_template("oxauth-errors.json", ctx),
    )

    generate_openid_keys(
        ctx["secret"]["oxauth_openid_jks_pass"],
        ctx["config"]["oxauth_openid_jks_fn"],
        ctx["config"]["oxauth_openid_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )

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
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"])
        )

    # # =======
    # # SCIM RS
    # # =======
    # ctx["scim_rs_client_id"] = get_or_set(
    #     "scim_rs_client_id",
    #     "{}!0008!{}".format(ctx["inumOrg"], join_quad_str(2)),
    # )

    # ctx["scim_rs_client_jks_fn"] = get_or_set("scim_rs_client_jks_fn",
    #                                           "/etc/certs/scim-rs.jks")
    # ctx["scim_rs_client_jwks_fn"] = get_or_set("scim_rs_client_jwks_fn",
    #                                            "/etc/certs/scim-rs-keys.json")
    # ctx["scim_rs_client_jks_pass"] = get_or_set(
    #     "scim_rs_client_jks_pass", get_random_chars())

    # ctx["scim_rs_client_jks_pass_encoded"] = get_or_set(
    #     "scim_rs_client_jks_pass_encoded",
    #     encrypt_text(ctx["scim_rs_client_jks_pass"], ctx["encoded_salt"]),
    # )

    # generate_openid_keys(
    #     ctx["scim_rs_client_jks_pass"],
    #     ctx["scim_rs_client_jks_fn"],
    #     ctx["scim_rs_client_jwks_fn"],
    #     ctx["default_openid_jks_dn_name"],
    # )

    # basedir, fn = os.path.split(ctx["scim_rs_client_jwks_fn"])
    # ctx["scim_rs_client_base64_jwks"] = get_or_set(
    #     "scim_rs_client_base64_jwks",
    #     encode_template(fn, ctx, basedir),
    # )

    # with open(ctx["scim_rs_client_jks_fn"], "rb") as fr:
    #     ctx["scim_rs_jks_base64"] = get_or_set(
    #         "scim_rs_jks_base64",
    #         encrypt_text(fr.read(), ctx["encoded_salt"]),
    #     )

    # # =======
    # # SCIM RP
    # # =======
    # ctx["scim_rp_client_id"] = get_or_set(
    #     "scim_rp_client_id",
    #     "{}!0008!{}".format(ctx["inumOrg"], join_quad_str(2)),
    # )

    # ctx["scim_rp_client_jks_fn"] = get_or_set("scim_rp_client_jks_fn", "/etc/certs/scim-rp.jks")
    # ctx["scim_rp_client_jwks_fn"] = get_or_set("scim_rp_client_jwks_fn", "/etc/certs/scim-rp-keys.json")
    # ctx["scim_rp_client_jks_pass"] = get_or_set("scim_rp_client_jks_pass", get_random_chars())

    # ctx["scim_rp_client_jks_pass_encoded"] = get_or_set(
    #     "scim_rp_client_jks_pass_encoded",
    #     encrypt_text(ctx["scim_rp_client_jks_pass"], ctx["encoded_salt"]),
    # )

    # generate_openid_keys(
    #     ctx["scim_rp_client_jks_pass"],
    #     ctx["scim_rp_client_jks_fn"],
    #     ctx["scim_rp_client_jwks_fn"],
    #     ctx["default_openid_jks_dn_name"],
    # )

    # basedir, fn = os.path.split(ctx["scim_rp_client_jwks_fn"])
    # ctx["scim_rp_client_base64_jwks"] = get_or_set(
    #     "scim_rp_client_base64_jwks",
    #     encode_template(fn, ctx, basedir),
    # )

    # with open(ctx["scim_rp_client_jks_fn"], "rb") as fr:
    #     ctx["scim_rp_jks_base64"] = get_or_set(
    #         "scim_rp_jks_base64",
    #         encrypt_text(fr.read(), ctx["encoded_salt"]),
    #     )

    # # ===========
    # # Passport RS
    # # ===========
    # ctx["passport_rs_client_id"] = get_or_set(
    #     "passport_rs_client_id",
    #     "{}!0008!{}".format(ctx["inumOrg"], join_quad_str(2)),
    # )

    # ctx["passport_rs_client_jks_fn"] = get_or_set("passport_rs_client_jks_fn", "/etc/certs/passport-rs.jks")
    # ctx["passport_rs_client_jwks_fn"] = get_or_set("passport_rs_client_jwks_fn", "/etc/certs/passport-rs-keys.json")
    # ctx["passport_rs_client_jks_pass"] = get_or_set(
    #     "passport_rs_client_jks_pass", get_random_chars())

    # ctx["passport_rs_client_jks_pass_encoded"] = get_or_set(
    #     "passport_rs_client_jks_pass_encoded",
    #     encrypt_text(ctx["passport_rs_client_jks_pass"], ctx["encoded_salt"]),
    # )

    # generate_openid_keys(
    #     ctx["passport_rs_client_jks_pass"],
    #     ctx["passport_rs_client_jks_fn"],
    #     ctx["passport_rs_client_jwks_fn"],
    #     ctx["default_openid_jks_dn_name"],
    # )

    # basedir, fn = os.path.split(ctx["passport_rs_client_jwks_fn"])
    # ctx["passport_rs_client_base64_jwks"] = get_or_set(
    #     "passport_rs_client_base64_jwks",
    #     encode_template(fn, ctx, basedir),
    # )

    # with open(ctx["passport_rs_client_jks_fn"], "rb") as fr:
    #     ctx["passport_rs_jks_base64"] = get_or_set(
    #         "passport_rs_jks_base64",
    #         encrypt_text(fr.read(), ctx["encoded_salt"])
    #     )

    # # ===========
    # # Passport RP
    # # ===========
    # ctx["passport_rp_client_id"] = get_or_set(
    #     "passport_rp_client_id",
    #     "{}!0008!{}".format(ctx["inumOrg"], join_quad_str(2)),
    # )

    # ctx["passport_rp_client_jks_pass"] = get_or_set(
    #     "passport_rp_client_jks_pass", get_random_chars())
    # ctx["passport_rp_client_jks_fn"] = get_or_set("passport_rp_client_jks_fn", "/etc/certs/passport-rp.jks")
    # ctx["passport_rp_client_jwks_fn"] = get_or_set("passport_rp_client_jwks_fn", "/etc/certs/passport-rp-keys.json")
    # ctx["passport_rp_client_cert_fn"] = get_or_set("passport_rp_client_cert_fn", "/etc/certs/passport-rp.pem")
    # ctx["passport_rp_client_cert_alg"] = get_or_set("passport_rp_client_cert_alg", "RS512")

    # cert_alias = gen_export_openid_keys(
    #     ctx["passport_rp_client_jks_pass"],
    #     ctx["passport_rp_client_jks_fn"],
    #     ctx["passport_rp_client_jwks_fn"],
    #     ctx["default_openid_jks_dn_name"],
    #     ctx["passport_rp_client_cert_alg"],
    #     ctx["passport_rp_client_cert_fn"],
    # )

    # basedir, fn = os.path.split(ctx["passport_rp_client_jwks_fn"])
    # ctx["passport_rp_client_base64_jwks"] = get_or_set(
    #     "passport_rp_client_base64_jwks",
    #     encode_template(fn, ctx, basedir),
    # )

    # ctx["passport_rp_client_cert_alias"] = get_or_set(
    #     "passport_rp_client_cert_alias", cert_alias
    # )

    # with open(ctx["passport_rp_client_jks_fn"], "rb") as fr:
    #     ctx["passport_rp_jks_base64"] = get_or_set(
    #         "passport_rp_jks_base64",
    #         encrypt_text(fr.read(), ctx["encoded_salt"]),
    #     )

    # with open(ctx["passport_rp_client_cert_fn"]) as fr:
    #     ctx["passport_rp_client_cert_base64"] = get_or_set(
    #         "passport_rp_client_cert_base64",
    #         encrypt_text(fr.read(), ctx["encoded_salt"]),
    #     )

    # # ===========
    # # Passport SP
    # # ===========

    # ctx["passportSpKeyPass"] = get_or_set("passportSpKeyPass", get_random_chars())
    # ctx["passportSpTLSCACert"] = get_or_set("passportSpTLSCACert", '/etc/certs/passport-sp.pem')
    # ctx["passportSpTLSCert"] = get_or_set("passportSpTLSCert", '/etc/certs/passport-sp.crt')
    # ctx["passportSpTLSKey"] = get_or_set("passportSpTLSKey", '/etc/certs/passport-sp.key')
    # ctx["passportSpJksPass"] = get_or_set("passportSpJksPass", get_random_chars())
    # ctx["passportSpJksFn"] = get_or_set("passportSpJksFn", '/etc/certs/passport-sp.jks')

    # generate_ssl_certkey(
    #     "passport-sp",
    #     ctx["passportSpKeyPass"],
    #     ctx["admin_email"],
    #     ctx["hostname"],
    #     ctx["orgName"],
    #     ctx["country_code"],
    #     ctx["state"],
    #     ctx["city"],
    # )
    # with open(ctx["passportSpTLSCert"]) as f:
    #     ctx["passport_sp_cert_base64"] = get_or_set(
    #         "passport_sp_cert_base64",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )
    # with open(ctx["passportSpTLSKey"]) as f:
    #     ctx["passport_sp_key_base64"] = get_or_set(
    #         "passport_sp_key_base64",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )

    # # ========
    # # oxAsimba
    # # ========
    # ctx["oxasimba_config_base64"] = get_or_set(
    #     "oxasimba_config_base64",
    #     encode_template("oxasimba-config.json", ctx),
    # )

    # # ================
    # # SSL cert and key
    # # ================
    # ssl_cert = "/etc/certs/gluu_https.crt"
    # ssl_key = "/etc/certs/gluu_https.key"

    # # generate self-signed SSL cert and key only if they aren't exist
    # if not(os.path.exists(ssl_cert) and os.path.exists(ssl_key)):
    #     generate_ssl_certkey(
    #         "gluu_https",
    #         admin_pw,
    #         ctx["admin_email"],
    #         ctx["hostname"],
    #         ctx["orgName"],
    #         ctx["country_code"],
    #         ctx["state"],
    #         ctx["city"],
    #     )

    # with open(ssl_cert) as f:
    #     ctx["ssl_cert"] = get_or_set("ssl_cert", f.read())

    # with open(ssl_key) as f:
    #     ctx["ssl_key"] = get_or_set("ssl_key", f.read())

    # # ================
    # # Extension config
    # # ================
    # ext_ctx = get_extension_config()
    # ctx.update(ext_ctx)

    # # ===================
    # # IDP3 (oxShibboleth)
    # # ===================
    # ctx["idp_client_id"] = get_or_set(
    #     "idp_client_id",
    #     "{}!0008!{}".format(ctx["inumOrg"], join_quad_str(2)),
    # )

    # ctx["idpClient_encoded_pw"] = get_or_set(
    #     "idpClient_encoded_pw",
    #     encrypt_text(get_random_chars(), ctx["encoded_salt"]),
    # )

    # ctx["oxidp_config_base64"] = get_or_set(
    #     "oxidp_config_base64",
    #     encode_template("oxidp-config.json", ctx)
    # )

    # ctx["shibJksFn"] = get_or_set("shibJksFn", "/etc/certs/shibIDP.jks")
    # ctx["shibJksPass"] = get_or_set("shibJksPass", get_random_chars())

    # ctx["encoded_shib_jks_pw"] = get_or_set(
    #     "encoded_shib_jks_pw",
    #     encrypt_text(ctx["shibJksPass"], ctx["encoded_salt"])
    # )

    # generate_ssl_certkey(
    #     "shibIDP",
    #     ctx["shibJksPass"],
    #     ctx["admin_email"],
    #     ctx["hostname"],
    #     ctx["orgName"],
    #     ctx["country_code"],
    #     ctx["state"],
    #     ctx["city"],
    # )
    # generate_keystore("shibIDP", ctx["hostname"], ctx["shibJksPass"])

    # with open("/etc/certs/shibIDP.crt") as f:
    #     ctx["shibIDP_cert"] = get_or_set(
    #         "shibIDP_cert",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )

    # with open("/etc/certs/shibIDP.key") as f:
    #     ctx["shibIDP_key"] = get_or_set(
    #         "shibIDP_key",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )

    # with open(ctx["shibJksFn"]) as f:
    #     ctx["shibIDP_jks_base64"] = get_or_set(
    #         "shibIDP_jks_base64",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )

    # ctx["shibboleth_version"] = get_or_set("shibboleth_version", "v3")
    # ctx["idp3Folder"] = get_or_set("idp3Folder", "/opt/shibboleth-idp")

    # idp3_signing_cert = "/etc/certs/idp-signing.crt"
    # idp3_signing_key = "/etc/certs/idp-signing.key"
    # generate_ssl_certkey(
    #     "idp-signing",
    #     ctx["shibJksPass"],
    #     ctx["admin_email"],
    #     ctx["hostname"],
    #     ctx["orgName"],
    #     ctx["country_code"],
    #     ctx["state"],
    #     ctx["city"],
    # )

    # with open(idp3_signing_cert) as f:
    #     ctx["idp3SigningCertificateText"] = get_or_set("idp3SigningCertificateText", f.read())
    # with open(idp3_signing_key) as f:
    #     ctx["idp3SigningKeyText"] = get_or_set("idp3SigningKeyText", f.read())

    # idp3_encryption_cert = "/etc/certs/idp-encryption.crt"
    # idp3_encryption_key = "/etc/certs/idp-encryption.key"
    # generate_ssl_certkey(
    #     "idp-encryption",
    #     ctx["shibJksPass"],
    #     ctx["admin_email"],
    #     ctx["hostname"],
    #     ctx["orgName"],
    #     ctx["country_code"],
    #     ctx["state"],
    #     ctx["city"],
    # )

    # with open(idp3_encryption_cert) as f:
    #     ctx["idp3EncryptionCertificateText"] = get_or_set("idp3EncryptionCertificateText", f.read())
    # with open(idp3_encryption_key) as f:
    #     ctx["idp3EncryptionKeyText"] = get_or_set("idp3EncryptionKeyText", f.read())

    # gen_idp3_key(ctx["shibJksPass"])
    # with open("/etc/certs/sealer.jks") as f:
    #     ctx["sealer_jks_base64"] = get_or_set(
    #         "sealer_jks_base64",
    #         encrypt_text(f.read(), ctx["encoded_salt"])
    #     )

    # populated config
    return ctx


def generate_ssl_certkey(suffix, passwd, email, domain, org_name,
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
        """-subj /C="{}"/ST="{}"/L="{}"/O="{}"/CN="{}"/emailAddress='{}'""".format(country_code, state, city, org_name, domain, email),

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


# def get_extension_config(basedir="/opt/config-init/static/extension"):
#     ctx = {}
#     for ext_type in os.listdir(basedir):
#         ext_type_dir = os.path.join(basedir, ext_type)

#         for fname in os.listdir(ext_type_dir):
#             filepath = os.path.join(ext_type_dir, fname)
#             ext_name = "{}_{}".format(ext_type, os.path.splitext(fname)[0].lower())

#             with open(filepath) as fd:
#                 ctx[ext_name] = get_or_set(
#                     ext_name,
#                     generate_base64_contents(fd.read())
#                 )
#     return ctx


def validate_country_code(ctx, param, value):
    if len(value) != 2:
        raise click.BadParameter("Country code must be two characters")
    return value


def generate_keystore(suffix, domain, keypasswd):
    # converts key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(domain),
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


def gen_idp3_key(shibJksPass):
    out, err, retcode = exec_cmd("java -classpath /opt/config-init/javalibs/idp3_cml_keygenerator.jar "
                                 "'org.xdi.oxshibboleth.keygenerator.KeyGenerator' "
                                 "/etc/certs {}".format(shibJksPass))
    return out, err, retcode


@click.group()
def cli():
    pass


@cli.command()
@click.option("--admin-pw", required=True, help="Password for admin access.")
@click.option("--email", required=True, help="Email for support.")
@click.option("--domain", required=True, help="Domain for Gluu Server.")
@click.option("--org-name", required=True, help="Organization name.")
@click.option("--country-code", required=True, help="Country code.", callback=validate_country_code)
@click.option("--state", required=True, help="State.")
@click.option("--city", required=True, help="City.")
@click.option("--ldap-type", default="opendj", type=click.Choice(["opendj", "openldap"]), help="LDAP choice")
@click.option("--base-inum", default="", help="Base inum.", show_default=True)
@click.option("--inum-org", default="", help="Organization inum.", show_default=True)
@click.option("--inum-appliance", default="", help="Appliance inum.", show_default=True)
def generate(admin_pw, email, domain, org_name, country_code, state, city,
             ldap_type, base_inum, inum_org, inum_appliance):
    """Generates initial config and secret and save them into KV.
    """
    wait_for(manager)

    click.echo("Generating config and secret.")
    # tolerancy before checking existing key
    time.sleep(5)
    ctx = generate_ctx(admin_pw, email, domain, org_name, country_code,
                       state, city, ldap_type, base_inum, inum_org,
                       inum_appliance)

    from pprint import pprint
    pprint(ctx)
    # click.echo("Saving config.")
    # for k, v in ctx.iteritems():
    #     manager.config.set(k, v)
    # click.echo("Config saved to backend")

    # ctx = {"_config": ctx}
    # ctx = json.dumps(ctx, indent=4)
    # with open(CONFIG_FILEPATH, "w") as f:
    #     f.write(ctx)
    #     click.echo("Config saved to {}".format(CONFIG_FILEPATH))


# @cli.command()
# @click.option()
# def load():
#     """Loads config and secret from JSON file and save them into KV.
#     """
#     _wrapper = namedtuple("Wrapper", "ctx type filepath")
#     wrappers = [
#         _wrapper(ctx=manager.config, type=CTX_CONFIG, filepath=CONFIG_FILEPATH),
#         _wrapper(ctx=manager.secret, type=CTX_SECRET, filepath=SECRET_FILEPATH),
#     ]

#     for wrapper in wrappers:
#         click.echo("Loading {} from {}.".format(wrapper.type, wrapper.filepath))
#         with open(wrapper.filepath, "r") as f:
#             ctx = json.loads(f.read())

#         if "_{}".format(wrapper.type) not in ctx:
#             click.echo("Missing '_{}' key.".format(wrapper.type))
#             return

#         # tolerancy before checking existing key
#         time.sleep(5)
#         for k, v in ctx["_{}".format(wrapper.type)].iteritems():
#             v = get_or_set(k, v)
#             wrapper.ctx.set(k, v)


# @cli.command()
# @click.option()
# def dump():
#     """Dumps config and secret from KV and save them into JSON file.
#     """
#     _wrapper = namedtuple("Wrapper", "ctx type filepath")
#     wrappers = [
#         _wrapper(ctx=manager.config, type=CTX_CONFIG, filepath=CONFIG_FILEPATH),
#         _wrapper(ctx=manager.secret, type=CTX_SECRET, filepath=SECRET_FILEPATH),
#     ]

#     for wrapper in wrappers:
#         click.echo("Dumping {} to {}.".format(wrapper.type, wrapper.filepath))
#         ctx = {"_{}".format(wrapper.type): wrapper.ctx.all()}
#         ctx = json.dumps(ctx, indent=4)
#         with open(wrapper.filepath, "w") as f:
#             f.write(ctx)


def _get_or_set(key, value, ctx_manager):
    overwrite_all = as_boolean(os.environ.get("GLUU_OVERWRITE_ALL", False))
    if overwrite_all:
        click.echo("  updating key {!r}".format(key))
        ctx_manager.set(key, value)
        return value

    # check existing value first
    _value = ctx_manager.get(key)
    if _value:
        click.echo("  ignoring existing key {!r}".format(key))
        return _value

    click.echo("  adding new key {!r}".format(key))
    return value


#: Gets value of existing config or sets a new one
get_or_set_config = partial(_get_or_set, ctx_manager=manager.config)

#: Gets value of existing secret or sets a new one
get_or_set_secret = partial(_get_or_set, ctx_manager=manager.secret)


def gen_export_openid_keys(jks_pass, jks_fn, jwks_fn, dn, cert_alg, cert_fn):
    generate_openid_keys(
        jks_pass,
        jks_fn,
        jwks_fn,
        dn,
    )

    with open(jwks_fn, "rb") as fr:
        pubkey = fr.read()
        for key in json.loads(pubkey)["keys"]:
            if key["alg"] == cert_alg:
                cert_alias = key["kid"]
                break

    export_openid_keys(
        jks_fn,
        jks_pass,
        cert_alias,
        cert_fn,
    )
    return cert_alias


def as_boolean(val, default=False):
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


if __name__ == "__main__":
    cli()
