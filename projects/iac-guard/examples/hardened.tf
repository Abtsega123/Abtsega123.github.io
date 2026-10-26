resource "aws_security_group" "admin" {
  name = "restricted-admin"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = "synthetic-demo-bucket"
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
