#!/usr/bin/python3
# EMCA: yet another ACME client (v0.1.1)

from __future__ import unicode_literals
import base64, binascii, json, os, re, sys
import copy, hashlib, subprocess, time, textwrap

if sys.version_info[0] < 3:
    from ConfigParser import ConfigParser
    from urllib2 import urlopen, HTTPError
else:
    from configparser import ConfigParser
    from urllib.request import urlopen
    from urllib.error import HTTPError

def http_resp(req):
    return req.getcode(), req.info(), req.read()

def http_except(ret, desc):
    raise Exception("unexpected HTTP status `%d' %s" % (ret, desc))

def my_base64(b):
    return base64.urlsafe_b64encode(b).decode("UTF-8").replace("=", "")

def my_write(f, b):
    (f if sys.version_info[0] < 3 else f.buffer).write(b + (
        b"" if len(b) == 0 or b[-1] == b"\n"[0] else b"\n"
    ))

def my_open(*args):
    try:
        return urlopen(*args)
    except HTTPError as e:
        return e

def my_run(cmd, input = None):
    proc = subprocess.Popen(
        cmd, stdin = None if input == None else subprocess.PIPE,
        stdout = subprocess.PIPE, stderr = subprocess.PIPE
    )
    out, err = proc.communicate(None if input == None else input)
    my_write(sys.stderr, err)
    if proc.returncode != 0:
        raise Exception("error running command: `%s'" % " ".join(cmd))
    return out

class Jws(object):
    def __init__(self, ca, acct):
        self.ca, self.acct = ca, acct

        out = re.sub(r":\n\s+", ":", my_run([
            "openssl", "rsa", "-in", self.acct, "-noout", "-text"
        ]).decode("UTF-8"))
        n, e = [re.search(pat, out).group(1) for pat in [
            r"modulus:(?:00:)*([0-9a-f:]+)", r"publicExponent: ([0-9]+)"
        ]]
        e = "%x" % int(e)

        self.hdr = {"alg": "RS256", "jwk": {
            "kty": "RSA", "n": my_base64(binascii.unhexlify(
                n.replace(":", "").encode("UTF-8")
            )), "e": my_base64(binascii.unhexlify(
                ("0" * (len(e) % 2) + e).encode("UTF-8")
            ))
        }}
        self.thumb = my_base64(hashlib.sha256(json.dumps(
            self.hdr["jwk"], sort_keys = True, separators = (",", ":")
        ).encode("UTF-8")).digest())

    def send(self, uri, payload):
        protected = copy.deepcopy(self.hdr)
        protected["nonce"] = \
            my_open(self.ca + "/directory").info()["Replay-Nonce"]
        data = {
            "header": self.hdr,
            "payload": my_base64(json.dumps(payload).encode("UTF-8")),
            "protected": my_base64(json.dumps(protected).encode("UTF-8"))
        }
        data["signature"] = my_base64(my_run(
            ["openssl", "dgst", "-sha256", "-sign", self.acct],
            ("%s.%s" % (data["protected"], data["payload"])).encode("UTF-8")
        ))
        req = my_open(
            self.ca + uri if uri.startswith("/") else uri,
            json.dumps(data).encode("UTF-8")
        )
        return req

def reg_acct(jws, agmt):
    ret, info, out = http_resp(jws.send(
        "/acme/new-reg", {"resource": "new-reg", "agreement": agmt}
    ))
    my_write(sys.stdout, out)
    if ret not in [201, 409]:
        http_except(ret, "in account registration")

def list_domains(csr):
    domains, out = [], my_run(["openssl", "req", "-in", csr, "-noout", "-text"])
    m = re.search(br"Subject:.*? CN=([^\s,;/]+)", out)
    m and domains.append(m.group(1).decode("UTF-8"))
    m = re.search(
        br"X509v3 Subject Alternative Name:\s+([^\n]+)\n",
        out, flags = re.MULTILINE
    )
    m and domains.extend(
        name[4:] for name in m.group(1).decode("UTF-8").split(", ")
        if name.startswith("DNS:")
    )
    return domains

def auth_domain(jws, domain, acme, tries, pause):
    ret, info, out = http_resp(jws.send("/acme/new-authz", {
        "resource": "new-authz", "identifier": {"type": "dns", "value": domain}
    }))
    if ret != 201:
        http_except(ret, "requesting challenge")
    chal = [
        c for c in json.loads(out.decode("UTF-8"))["challenges"]
        if c["type"] == "http-01"
    ]
    assert len(chal) == 1
    token = chal[0]["token"]
    assert not re.search(r"[^A-Za-z0-9_-]", token)

    path, text = os.path.join(acme, token), "%s.%s" % (token, jws.thumb)
    with open(path, "w") as f:
        f.write(text)
    ret, info, out = http_resp(jws.send(chal[0]["uri"], {
        "resource": "challenge", "keyAuthorization": text
    }))
    if ret != 202:
        http_except(ret,
            "responding to challenge for domain `%s'" % domain
        )

    uri, i = info["Location"], tries
    while i != 0:
        ret, info, out = http_resp(my_open(uri))
        if ret >= 400:
            http_except(ret,
                "polling challenge status for domain `%s'" % domain
            )
        status = json.loads(out.decode("UTF-8"))["status"]
        if status == "pending":
            time.sleep(pause)
            i -= 1
        else:
            os.remove(path)
            my_write(sys.stdout, out)
            if status == "valid":
                break
            else:
                raise Exception("failed challenge for domain `%s'" % domain)
    else:
        os.remove(path)
        raise Exception("challenge time out for domain `%s'" % domain)

def sign_cert(jws, csr):
    ret, info, out = http_resp(jws.send("/acme/new-cert", {
        "resource": "new-cert", "csr": my_base64(my_run([
            "openssl", "req", "-in", csr, "-outform", "DER"
        ]))
    }))
    if ret != 201:
        my_write(sys.stderr, out)
        http_except(ret, "signing certificate")
    sys.stdout.write(
        "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" %
        "\n".join(textwrap.wrap(base64.b64encode(out).decode("UTF-8"), 64))
    )

def main(argv):
    if len(argv) != 3 or argv[1] not in ["reg", "auth", "sign"]:
        sys.stderr.write("Usage: %s [reg | auth | sign] cfg_file\n" % argv[0])
        sys.exit(1)

    cfg = ConfigParser()
    cfg.read(argv[2])
    cfg = dict(cfg.items("emca"))
    jws = Jws(cfg["ca"], cfg["acct"])

    if argv[1] == "reg":
        reg_acct(jws, cfg["agmt"])
    elif argv[1] == "auth":
        [auth_domain(
            jws, domain, cfg["acme"], int(cfg["tries"]), int(cfg["pause"])
        ) for domain in list_domains(cfg["csr"])]
    else:
        sign_cert(jws, cfg["csr"])
    sys.exit(0)

if __name__ == "__main__":
    main(sys.argv)

