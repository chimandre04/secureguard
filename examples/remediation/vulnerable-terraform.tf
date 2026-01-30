# Example Terraform with security misconfigurations

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"  # CRITICAL: Public access!

  # Missing encryption configuration
}

resource "aws_db_instance" "main" {
  identifier = "main-db"
  engine     = "postgres"

  storage_encrypted     = false  # HIGH: No encryption!
  publicly_accessible   = true   # CRITICAL: Public access!
  backup_retention_period = 0    # MEDIUM: No backups!
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HIGH: Unrestricted SSH!
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-west-2a"
  size             = 100
  encrypted        = false  # HIGH: No encryption!
}
