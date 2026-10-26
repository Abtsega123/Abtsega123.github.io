resource "aws_security_group" "admin" {
  name = "demo-admin"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "demo" {
  bucket = "synthetic-demo-bucket"
  acl = "public-read"
}
resource "aws_db_instance" "demo" {
  identifier = "demo-db"
  publicly_accessible = true
}
resource "aws_ebs_volume" "demo" {
  encrypted = false
}
