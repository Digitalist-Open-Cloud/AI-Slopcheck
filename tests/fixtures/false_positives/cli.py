s3api(ep, "head-object", "--bucket", mb, "--key", PROV_NYCKEL, "--version-id", version)
kubectl("exec", "-n", "ingress-nginx", pod, "-c", "nginx", "--", "nginx", "-T", check=False)
SCRIPT = r"""
SELECT 1 FROM t
""" + _SHARED + r"""
WHERE x = 1
"""
