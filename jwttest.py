import jwt


def read_file(path: str) -> bytes:
    with open(path, "rb") as fd:
        return fd.read()


def main() -> None:
    """Decodes the JWT claim. The claim and the public key can be produced by
    running main.go."""

    pub_key = read_file("public.pem")
    claims = read_file("claims.txt")
    print("claims: ", claims)
    xx = jwt.decode(str(claims, "utf-8"), pub_key, algorithm="EC384")
    print("Decoded", xx)


main()
