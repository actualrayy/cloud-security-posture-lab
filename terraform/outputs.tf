output "vpc_id" {
  value = aws_vpc.lab.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "security_group_id" {
  value = aws_security_group.baseline.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure_baseline.id
}
