# -----------------------------------------------------------------------------
# Author: Jelle Vandekerckhove
# Firm: Odileon
# Description: 
# This Terraform configuration demonstrates how to configure AWS CloudFront 
# to support HTTPS enforcement while allowing Let's Encrypt ACME HTTP 
# challenges for certificate validation.
# 
# Feel free to use this configuration as a reference. Pull requests and 
# suggestions are welcome! 
# -----------------------------------------------------------------------------

resource "aws_cloudfront_distribution" "cf" {
  origin {
    domain_name = data.aws_lb.nlb.dns_name
    origin_id   = "k8s-nlb-origin"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "match-viewer"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 60
    }
  }

  enabled         = true
  is_ipv6_enabled = true
  http_version    = "http2"
  price_class     = "PriceClass_100"
  comment         = "Kubernetes CloudFront Distribution"
  aliases         = ["example.com"]
  web_acl_id      = aws_wafv2_web_acl.main.arn

  # Default behavior: enforce HTTPS
  default_cache_behavior {
    cache_policy_id            = data.aws_cloudfront_cache_policy.CachingDisabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.AllViewer.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.SimpleCors.id
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["HEAD", "GET"]
    target_origin_id           = "k8s-nlb-origin"
    viewer_protocol_policy     = "redirect-to-https"
  }

  # Special behavior for ACME HTTP challenge
  ordered_cache_behavior {
    path_pattern               = "/.well-known/acme-challenge/*"
    target_origin_id           = "k8s-nlb-origin"
    viewer_protocol_policy     = "allow-all" # Allow HTTP and HTTPS

    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = aws_cloudfront_cache_policy.acme.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.acme.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn            = data.aws_acm_certificate.main.arn
    ssl_support_method             = "sni-only"
    cloudfront_default_certificate = false
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = {
    Name = "K8S-CloudFront"
  }
}

resource "aws_cloudfront_cache_policy" "acme" {
  name        = "acme-cache-policy-${var.env}"
  comment     = "Cache policy for ACME validation"
  default_ttl = 86400
  min_ttl     = 3600
  max_ttl     = 86400

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers         = ["Host"]
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_origin_request_policy" "acme" {
  name = "acme-origin-request-policy-${var.env}"

  headers_config {
    header_behavior = "whitelist"
    headers         = ["Host"]
  }

  cookies_config {
    cookie_behavior = "none"
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}
