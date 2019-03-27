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
from functools import partial

import click
import pyDes

from gluulib import get_manager
from wait_for import wait_for


# Default charset
_DEFAULT_CHARS = "".join([string.ascii_uppercase,
                          string.digits,
                          string.lowercase])

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

    ctx["config"]["fido2ConfigFolder"] = get_or_set_config("fido2ConfigFolder", "/etc/gluu/conf/fido2")

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

    ctx["config"]["ldap_binddn"] = get_or_set_config("ldap_binddn", ldap_binddn)

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

    # =======
    # SCIM RS
    # =======
    ctx["config"]["scim_rs_client_id"] = get_or_set_config(
        "scim_rs_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
    )

    ctx["config"]["scim_rs_client_jks_fn"] = get_or_set_config(
        "scim_rs_client_jks_fn", "/etc/certs/scim-rs.jks")

    ctx["config"]["scim_rs_client_jwks_fn"] = get_or_set_config(
        "scim_rs_client_jwks_fn", "/etc/certs/scim-rs-keys.json")

    ctx["secret"]["scim_rs_client_jks_pass"] = get_or_set_secret(
        "scim_rs_client_jks_pass", get_random_chars())

    ctx["secret"]["scim_rs_client_jks_pass_encoded"] = get_or_set_secret(
        "scim_rs_client_jks_pass_encoded",
        encrypt_text(ctx["secret"]["scim_rs_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    generate_openid_keys(
        ctx["secret"]["scim_rs_client_jks_pass"],
        ctx["config"]["scim_rs_client_jks_fn"],
        ctx["config"]["scim_rs_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )

    basedir, fn = os.path.split(ctx["config"]["scim_rs_client_jwks_fn"])
    ctx["secret"]["scim_rs_client_base64_jwks"] = get_or_set_secret(
        "scim_rs_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["scim_rs_client_jks_fn"], "rb") as fr:
        ctx["secret"]["scim_rs_jks_base64"] = get_or_set_secret(
            "scim_rs_jks_base64",
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"]),
        )

    # =======
    # SCIM RP
    # =======
    ctx["config"]["scim_rp_client_id"] = get_or_set_config(
        "scim_rp_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
    )

    ctx["config"]["scim_rp_client_jks_fn"] = get_or_set_config(
        "scim_rp_client_jks_fn", "/etc/certs/scim-rp.jks")

    ctx["config"]["scim_rp_client_jwks_fn"] = get_or_set_config(
        "scim_rp_client_jwks_fn", "/etc/certs/scim-rp-keys.json")

    ctx["secret"]["scim_rp_client_jks_pass"] = get_or_set_secret(
        "scim_rp_client_jks_pass", get_random_chars())

    ctx["secret"]["scim_rp_client_jks_pass_encoded"] = get_or_set_secret(
        "scim_rp_client_jks_pass_encoded",
        encrypt_text(ctx["secret"]["scim_rp_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    generate_openid_keys(
        ctx["secret"]["scim_rp_client_jks_pass"],
        ctx["config"]["scim_rp_client_jks_fn"],
        ctx["config"]["scim_rp_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )

    basedir, fn = os.path.split(ctx["config"]["scim_rp_client_jwks_fn"])
    ctx["secret"]["scim_rp_client_base64_jwks"] = get_or_set_secret(
        "scim_rp_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["scim_rp_client_jks_fn"], "rb") as fr:
        ctx["secret"]["scim_rp_jks_base64"] = get_or_set_secret(
            "scim_rp_jks_base64",
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"]),
        )

    ctx["config"]["scim_resource_oxid"] = get_or_set_config(
        "scim_resource_oxid",
        str(uuid.uuid4()),
    )

    # ===========
    # Passport RS
    # ===========
    ctx["config"]["passport_rs_client_id"] = get_or_set_config(
        "passport_rs_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
    )

    ctx["config"]["passport_rs_client_jks_fn"] = get_or_set_config(
        "passport_rs_client_jks_fn", "/etc/certs/passport-rs.jks")

    ctx["config"]["passport_rs_client_jwks_fn"] = get_or_set_config(
        "passport_rs_client_jwks_fn", "/etc/certs/passport-rs-keys.json")

    ctx["secret"]["passport_rs_client_jks_pass"] = get_or_set_secret(
        "passport_rs_client_jks_pass", get_random_chars())

    ctx["secret"]["passport_rs_client_jks_pass_encoded"] = get_or_set_secret(
        "passport_rs_client_jks_pass_encoded",
        encrypt_text(ctx["secret"]["passport_rs_client_jks_pass"], ctx["secret"]["encoded_salt"]),
    )

    generate_openid_keys(
        ctx["secret"]["passport_rs_client_jks_pass"],
        ctx["config"]["passport_rs_client_jks_fn"],
        ctx["config"]["passport_rs_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
    )

    basedir, fn = os.path.split(ctx["config"]["passport_rs_client_jwks_fn"])
    ctx["secret"]["passport_rs_client_base64_jwks"] = get_or_set_secret(
        "passport_rs_client_base64_jwks",
        encode_template(fn, ctx, basedir),
    )

    with open(ctx["config"]["passport_rs_client_jks_fn"], "rb") as fr:
        ctx["secret"]["passport_rs_jks_base64"] = get_or_set_secret(
            "passport_rs_jks_base64",
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"])
        )

    # ===========
    # Passport RP
    # ===========
    ctx["config"]["passport_rp_client_id"] = get_or_set_config(
        "passport_rp_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
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

    cert_alias = gen_export_openid_keys(
        ctx["secret"]["passport_rp_client_jks_pass"],
        ctx["config"]["passport_rp_client_jks_fn"],
        ctx["config"]["passport_rp_client_jwks_fn"],
        ctx["config"]["default_openid_jks_dn_name"],
        ctx["config"]["passport_rp_client_cert_alg"],
        ctx["config"]["passport_rp_client_cert_fn"],
    )

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
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"]),
        )

    with open(ctx["config"]["passport_rp_client_cert_fn"]) as fr:
        ctx["secret"]["passport_rp_client_cert_base64"] = get_or_set_secret(
            "passport_rp_client_cert_base64",
            encrypt_text(fr.read(), ctx["secret"]["encoded_salt"]),
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
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open(ctx["config"]["passportSpTLSKey"]) as f:
        ctx["secret"]["passport_sp_key_base64"] = get_or_set_secret(
            "passport_sp_key_base64",
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    # ========
    # oxAsimba
    # ========
    ctx["secret"]["oxasimba_config_base64"] = get_or_set_secret(
        "oxasimba_config_base64",
        encode_template("oxasimba-config.json", ctx),
    )

    # ================
    # SSL cert and key
    # ================
    ssl_cert = "/etc/certs/gluu_https.crt"
    ssl_key = "/etc/certs/gluu_https.key"

    # generate self-signed SSL cert and key only if they aren't exist
    if not(os.path.exists(ssl_cert) and os.path.exists(ssl_key)):
        generate_ssl_certkey(
            "gluu_https",
            admin_pw,
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

    # ================
    # Extension config
    # ================
    ext_ctx = get_extension_config()
    ctx["config"].update(ext_ctx)

    # ===================
    # IDP3 (oxShibboleth)
    # ===================
    ctx["config"]["idp_client_id"] = get_or_set_config(
        "idp_client_id",
        "{}!0008!{}".format(ctx["config"]["inumOrg"], join_quad_str(2)),
    )

    ctx["secret"]["idpClient_encoded_pw"] = get_or_set_secret(
        "idpClient_encoded_pw",
        encrypt_text(get_random_chars(), ctx["secret"]["encoded_salt"]),
    )

    ctx["secret"]["oxidp_config_base64"] = get_or_set_secret(
        "oxidp_config_base64",
        encode_template("oxidp-config.json", ctx)
    )

    ctx["config"]["shibJksFn"] = get_or_set_config("shibJksFn", "/etc/certs/shibIDP.jks")

    ctx["secret"]["shibJksPass"] = get_or_set_secret("shibJksPass", get_random_chars())

    ctx["secret"]["encoded_shib_jks_pw"] = get_or_set_secret(
        "encoded_shib_jks_pw",
        encrypt_text(ctx["secret"]["shibJksPass"], ctx["secret"]["encoded_salt"])
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
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open("/etc/certs/shibIDP.key") as f:
        ctx["secret"]["shibIDP_key"] = get_or_set_secret(
            "shibIDP_key",
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
        )

    with open(ctx["config"]["shibJksFn"]) as f:
        ctx["secret"]["shibIDP_jks_base64"] = get_or_set_secret(
            "shibIDP_jks_base64",
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
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

    gen_idp3_key(ctx["secret"]["shibJksPass"])

    with open("/etc/certs/sealer.jks") as f:
        ctx["secret"]["sealer_jks_base64"] = get_or_set_secret(
            "sealer_jks_base64",
            encrypt_text(f.read(), ctx["secret"]["encoded_salt"])
        )

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


def get_extension_config(basedir="/opt/config-init/static/extension"):
    ctx = {}
    for ext_type in os.listdir(basedir):
        ext_type_dir = os.path.join(basedir, ext_type)

        for fname in os.listdir(ext_type_dir):
            filepath = os.path.join(ext_type_dir, fname)
            ext_name = "{}_{}".format(ext_type, os.path.splitext(fname)[0].lower())

            with open(filepath) as fd:
                ctx[ext_name] = get_or_set_config(
                    ext_name,
                    generate_base64_contents(fd.read())
                )
    return ctx


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


def _get_or_set(key, value, ctx_manager):
    overwrite_all = as_boolean(os.environ.get("GLUU_OVERWRITE_ALL", False))
    if overwrite_all:
        click.echo("  updating {} {!r}".format(ctx_manager.adapter.type, key))
        # ctx_manager.set(key, value)
        return value

    # check existing value first
    _value = ctx_manager.get(key)
    if _value:
        click.echo("  ignoring {} {!r}".format(ctx_manager.adapter.type, key))
        return _value

    click.echo("  adding {} {!r}".format(ctx_manager.adapter.type, key))
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


# ============
# CLI commands
# ============


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
    def _save_generated_ctx(ctx_manager, filepath, data):
        click.echo("Saving {} to backend.".format(ctx_manager.adapter.type))

        for k, v in data.iteritems():
            ctx_manager.set(k, v)

        click.echo("Saving {} to {}.".format(ctx_manager.adapter.type, filepath))
        data = {"_{}".format(ctx_manager.adapter.type): data}
        data = json.dumps(data, indent=4)

        with open(filepath, "w") as f:
            f.write(data)

    wait_for(manager)

    click.echo("Generating config and secret.")
    # tolerancy before checking existing key
    time.sleep(5)
    ctx = generate_ctx(admin_pw, email, domain, org_name, country_code,
                       state, city, ldap_type, base_inum, inum_org,
                       inum_appliance)

    wrappers = [
        (manager.config, CONFIG_FILEPATH),
        (manager.secret, SECRET_FILEPATH),
    ]
    for wrapper in wrappers:
        _save_generated_ctx(wrapper[0], wrapper[1], ctx[wrapper[0].adapter.type])


@cli.command()
def load():
    """Loads config and secret from JSON file and save them into KV.
    """
    def _load_from_file(ctx_manager, filepath):
        click.echo("Loading {} from {}.".format(
            ctx_manager.adapter.type, filepath))

        with open(filepath, "r") as f:
            data = json.loads(f.read())

        if "_{}".format(ctx_manager.adapter.type) not in data:
            click.echo("Missing '_{}' key.".format(ctx_manager.adapter.type))
            return

        # tolerancy before checking existing key
        time.sleep(5)
        for k, v in data["_{}".format(ctx_manager.adapter.type)].iteritems():
            v = _get_or_set(k, v, ctx_manager)
            ctx_manager.set(k, v)

    wait_for(manager)

    wrappers = [
        (manager.config, CONFIG_FILEPATH),
        (manager.secret, SECRET_FILEPATH),
    ]
    for wrapper in wrappers:
        _load_from_file(wrapper[0], wrapper[1])


@cli.command()
def dump():
    """Dumps config and secret from KV and save them into JSON file.
    """
    def _dump_to_file(ctx_manager, filepath):
        click.echo("Saving {} to {}.".format(
            ctx_manager.adapter.type, filepath))

        data = {"_{}".format(ctx_manager.adapter.type): ctx_manager.all()}
        data = json.dumps(data, indent=4)
        with open(filepath, "w") as f:
            f.write(data)

    wait_for(manager)

    wrappers = [
        (manager.config, CONFIG_FILEPATH),
        (manager.secret, SECRET_FILEPATH),
    ]
    for wrapper in wrappers:
        _dump_to_file(wrapper[0], wrapper[1])


if __name__ == "__main__":
    cli()
