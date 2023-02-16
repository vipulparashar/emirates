terraform {
  backend "s3" {
    bucket = "emi-terraform"
    region = "us-east-1"
    key    = "nonprod/us-east-1/eks/nonproduction01/eks.tfstate"
  }
}
