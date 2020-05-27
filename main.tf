resource "aws_kms_key" "mykey" {
   description             = "This key is used to encrypt bucket objects"
   deletion_window_in_days = 10
   tags = {
    Name        = "My KMS Key"
    Environment = "Sandbox"
    Owner       = "Rohit Ranjan"
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "rohit-terraform-27-may-2020"
  acl = "log-delivery-write"
  region   = "us-east-1"

  tags = {
    Name        = "My S3 test bucket 22 May 2020"
    Environment = "Sandbox"
    Owner       = "Rohit Ranjan",
    DataType    = "Test files"
  }

  logging {
    target_bucket = "rohit-terraform-27-may-2020"
    target_prefix = "s3logs/us-east-1/"
   # acl = "log-delivery-write"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

}
