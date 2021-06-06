#!/usr/bin/python
# EMCA: yet another ACME client (v0.1.3)

from __future__ import unicode_literals
import base64, binascii, json, os, re, sys
import copy, hashlib, subprocess, time

if sys.version_info[0] < 3:
    from ConfigParser import ConfigParser
    from urllib2 import urlopen, Request, HTTPError
else:
    from configparser import ConfigParser
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError

def my_base64(b):
    return base64.urlsafe_b64encode(b).decode("UTF-8").replace("=", "")

def my_write(f, b):
    (f if sys.version_info[0] < 3 else f.buffer).write(b + (
        b"" if len(b) == 0 or b[-1] == b"\n"[0] else b"\n"
    ))

def my_err(out, desc):
    my_write(sys.stderr, out)
    raise Exception(desc)

def my_open(req):
    try:
        return urlopen(req)
    except HTTPError as e:
        return e

def http_chk(desc, req, decode = True):
    ret, info, out = req.getcode(), req.info(), req.read()
    if ret not in [200, 201]:
        my_err(out, "unexpected HTTP status `%d' %s" % (ret, desc))
    return info, json.loads(out.decode("UTF-8")) if decode else out

def my_run(cmd, input = None):
    proc = subprocess.Popen(
        cmd, stdout = subprocess.PIPE,
        stdin = None if input == None else subprocess.PIPE
    )
    out = proc.communicate(input)[0]
    if proc.returncode != 0:
        raise Exception("error running command: `%s'" % " ".join(cmd))
    return out

def jws_mk(acct):
    jws = {"acct": acct}
    out = re.sub(r":\n\s+", ":", re.sub(r":\s+", ":", my_run([
        "openssl", "rsa", "-in", jws["acct"], "-noout", "-text"
    ]).decode("UTF-8")))
    n, e = [re.search(pat, out).group(1) for pat in [
        r"modulus:(?:00:)*([0-9a-f:]+)", r"publicExponent:([0-9]+)"
    ]]
    e = "%x" % int(e)

    jws["hdr"] = {"alg": "RS256", "jwk": {
        "kty": "RSA", "n": my_base64(binascii.unhexlify(
            n.replace(":", "").encode("UTF-8")
        )), "e": my_base64(binascii.unhexlify(
            ("0" * (len(e) % 2) + e).encode("UTF-8")
        ))
    }}
    jws["thumb"] = my_base64(hashlib.sha256(json.dumps(
        jws["hdr"]["jwk"], sort_keys = True, separators = (",", ":")
    ).encode("UTF-8")).digest())
    return jws

def jws_send(jws, url, payload):
    protected = copy.deepcopy(jws["hdr"])
    protected.update([("url", url),
        ("nonce", my_open(jws["ca"]["newNonce"]).info()["Replay-Nonce"])])
    data = {
        "payload": "" if payload == None else
            my_base64(json.dumps(payload).encode("UTF-8")),
        "protected": my_base64(json.dumps(protected).encode("UTF-8"))
    }
    data["signature"] = my_base64(my_run(
        ["openssl", "dgst", "-sha256", "-sign", jws["acct"]],
        ("%s.%s" % (data["protected"], data["payload"])).encode("UTF-8")
    ))
    req = Request(url, json.dumps(data).encode("UTF-8"),
        headers = {"Content-Type": "application/jose+json"})
    return my_open(req)

def poll_mk(tries, pause):
    def poll(jws, url):
        i = tries
        while i != 0:
            out = http_chk("polling `%s'" % url,
                jws_send(jws, url, None), False)[1]
            out = json.loads(out.decode("UTF-8")), out
            if out[0]["status"] != "pending":
                break
            time.sleep(pause)
            i -= 1
        else:
            out[0]["status"] = "timeout"
        return out
    return poll

def reg_acct(jws, ca):
    jws["ca"] = http_chk("loading directory", my_open(ca))[1]
    jws["hdr"]["kid"] = http_chk("in account registration", jws_send(
        jws, jws["ca"]["newAccount"], {"termsOfServiceAgreed": True}
    ))[0]["Location"]
    jws["hdr"].pop("jwk")

def order_mk(jws, csr):
    domains, out = [], my_run(["openssl", "req", "-in", csr, "-noout", "-text"])
    m = re.search(br"Subject:.*? CN *= *([^\s,;/]+)", out)
    m and domains.append(m.group(1).decode("UTF-8"))
    m = re.search(
        br"X509v3 Subject Alternative Name:\s+([^\n]+)\n",
        out, flags = re.MULTILINE
    )
    m and domains.extend(
        name[4:] for name in m.group(1).decode("UTF-8").split(", ")
        if name.startswith("DNS:")
    )
    return http_chk("requesting order", jws_send(jws, jws["ca"]["newOrder"], {
        "identifiers": [{"type": "dns", "value": domain} for domain in domains]
    }))[1]

def auth_domain(jws, acme, url, poll):
    out = http_chk("requesting challenge", jws_send(jws, url, None))[1]
    chal = [c for c in out["challenges"] if c["type"] == "http-01"]
    token = chal[0]["token"]
    assert len(chal) == 1 and not re.search(r"[^A-Za-z0-9_-]", token)

    path, text = os.path.join(acme, token), "%s.%s" % (token, jws["thumb"])
    with open(path, "w") as f:
        f.write(text)
    out = poll(jws, http_chk(
        "answering challenge `%s'" % url, jws_send(jws, chal[0]["url"], {})
    )[0]["Location"])
    os.remove(path)
    if out[0]["status"] != "valid":
        my_err(out[1], "authorisation %s for `%s'" % (out[0]["status"], url))

def sign_cert(jws, csr, url, poll):
    req = jws_send(jws, url, {"csr": my_base64(my_run([
        "openssl", "req", "-in", csr, "-outform", "DER"]))})
    out = poll(jws, http_chk("finalising certificate", req)[0]["Location"])
    if out[0]["status"] != "valid":
        my_err(out[1], "finalisation %s for `%s'" % (out[0]["status"], url))
    my_write(sys.stdout, http_chk("downloading certificate",
        jws_send(jws, out[0]["certificate"], None), False)[1])

def main(argv):
    if len(argv) != 2:
        sys.stderr.write("Usage: %s cfg_file\n" % argv[0])
        sys.exit(1)

    cfg = ConfigParser()
    cfg.read(argv[1])
    cfg = dict(cfg.items("emca"))
    jws = jws_mk(cfg["acct"])
    poll = poll_mk(int(cfg["tries"]), int(cfg["pause"]))

    reg_acct(jws, cfg["ca"])
    sys.stderr.write("account is `%s'\n" % jws["hdr"]["kid"])
    order = order_mk(jws, cfg["csr"])
    for url in order["authorizations"]:
        sys.stderr.write("authorising `%s'\n" % url)
        auth_domain(jws, cfg["acme"], url, poll)
    sys.stderr.write("finalising `%s'\n" % order["finalize"])
    sign_cert(jws, cfg["csr"], order["finalize"], poll)
    sys.exit(0)

if __name__ == "__main__":
    main(sys.argv)

