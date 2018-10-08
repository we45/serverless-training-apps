resource "aws_dynamodb_table" "ctf_user_table" {
  name = "ctf_users"
  hash_key = "email"
  read_capacity = 100
  write_capacity = 100

  attribute {
    name = "email"
    type = "S"
  }
}

resource "aws_dynamodb_table" "ctf_resume_table" {
  name = "ctf_resumes"
  hash_key = "filename"
  read_capacity = 100
  write_capacity = 100

  attribute {
    name = "filename"
    type = "S"
  }
}

resource "aws_s3_bucket" "ctf_resume_bucket" {
  bucket = "sls-ctf-resumes"
}

data "aws_iam_policy_document" "ctf_user_policy_doc" {
  statement {
    sid = "1"
    actions = [
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:PutObject"
    ]

    resources = ["${aws_s3_bucket.ctf_resume_bucket.arn}"]
  }

  statement {
    actions = [
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:GetItem",
      "dynamodb:PutItem"
    ]

    resources = [
      "${aws_dynamodb_table.ctf_user_table.arn}",
      "${aws_dynamodb_table.ctf_resume_table.arn}"
    ]
  }
}

resource "aws_iam_policy" "ctf_policy" {
  name = "sls_ctf_policy"
  description = "Policy for Serverless CTF"
  policy = "${data.aws_iam_policy_document.ctf_user_policy_doc.json}"
}