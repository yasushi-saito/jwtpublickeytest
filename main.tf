# Builds the backend cluster "test0" used for testing.
terraform {
  required_version = ">=0.13"
}

resource "tls_private_key" "jwt" {
  algorithm = "ECDSA"
  ecdsa_curve = "P384"
}
