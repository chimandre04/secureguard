# Example Terraform file with security misconfigurations
# For demonstration purposes only

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # CRITICAL: Public access!
}

resource "aws_db_instance" "exposed_db" {
  identifier           = "my-database"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "password123"
  publicly_accessible = true  # CRITICAL: Publicly accessible!
  storage_encrypted   = false # HIGH: No encryption!
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HIGH: Unrestricted access!
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size             = 40
  encrypted        = false  # HIGH: No encryption!
}
