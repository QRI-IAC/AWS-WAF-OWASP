#
# This is our WAF ACL with each rule defined and prioritized accordingly.
#
resource aws_wafv2_web_acl waf_v2_acl {
  name        = "${var.wafv2_prefix}-owasp-acl"
  description = "OWASP ACL WAF rules for local domain"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
    metric_name                 = replace("${var.wafv2_prefix}owaspacl", "/[^0-9A-Za-z]/", "")
    sampled_requests_enabled    = var.sampled_requests_enabled
  }

  # Whitelist rule sets
  rule {
      name                          = "${var.wafv2_prefix}-whitelist"
      priority                      = 10

      action {
        allow {}
      }
      
      statement {
        rule_group_reference_statement {
          arn                       = aws_wafv2_rule_group.whitelist.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
      }
  }

  rule {
      name                          = "${var.wafv2_prefix}-blacklist"
      priority                      = 20

      action {
        count {}
      }
      
      statement {
        rule_group_reference_statement {
          arn                       = aws_wafv2_rule_group.blacklist.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}blacklist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
      }
  }
      
  tags = var.tags
}

#########################################################################################################
## Rulegroup Whitelist


resource aws_wafv2_rule_group whitelist {
  name        = "${var.wafv2_prefix}-rulegroup-whitelist"
  description = "A rule group containing all whitelisted statements"
  scope       = "REGIONAL"
  capacity    = 700 
  

  visibility_config {
    cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
    metric_name = replace("${var.wafv2_prefix}rulegroupwhitelist", "/[^0-9A-Za-z]/", "")
    sampled_requests_enabled    = var.sampled_requests_enabled
  }

  rule {
    name      = "${var.wafv2_prefix}-match-whitelisted-ips"
    priority  = 10

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.whitelisted_elastic_ips.arn
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelistedips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  }

  rule {
    name      = "${var.wafv2_prefix}-match-whitelisted-elastic-ips"
    priority  = 20

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.whitelisted_ips.arn
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelistedelasticips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  }

  /*
  rule {
    name = "${var.wafv2_prefix}-whitelisted-user-agent-header"
    priority  = 30

    action {
      allow {}
    }


    statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = var.whitelisted_user_agent_header
            
            field_to_match {
              single_query_argument {
                name = "user-agent"
              }
            }

            text_transformation {
              priority            = 1
              type                = "NONE"
            }
          }

    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelisteduseragent", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }
  */
  
}


#########################################################################################################
## Rulegroup Blacklist

resource aws_wafv2_rule_group blacklist {
  name        = "${var.wafv2_prefix}-rulegroup-blacklist"
  description = "A rule group containing all blacklisted statements"
  scope       = "REGIONAL"
  capacity    = 1000

  visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}rulegroupblacklist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
  }


  ## 1.
  ## OWASP Top 10 A1
  ## Mitigate SQL Injection Attacks
  ## Matches attempted SQLi patterns in the URI, QUERY_STRING, BODY, COOKIES

  rule {
    name      = "${var.wafv2_prefix}-mitigate-sqli"
    priority  = 10

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          sqli_match_statement {
            field_to_match {
              body {}
            }

             text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }

            text_transformation {
              priority = 3
              type     = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }


      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}mitigatesqli", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }


  ## 2.
  ## OWASP Top 10 A2
  ## Blacklist bad/hijacked JWT tokens or session IDs
  ## Matches the specific values in the cookie or Authorization header
  ## for JWT it is sufficient to check the signature

  rule {
    name      = "${var.wafv2_prefix}-detect-bad-auth-tokens"
    priority  = 20

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
            
            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "example-session-id"
            
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectbadauthtokens", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }


  ## 3.
  ## OWASP Top 10 A3
  ## Mitigate Cross Site Scripting Attacks
  ## Matches attempted XSS patterns in the URI, QUERY_STRING, BODY, COOKIES

  rule {
    name      = "${var.wafv2_prefix}-mitigate-xss"
    priority  = 30

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }

             text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }

            text_transformation {
              priority = 3
              type     = "COMPRESS_WHITE_SPACE"
            }
          }
          
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}mitigatexss", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 4.
  ## OWASP Top 10 A4
  ## Path Traversal, LFI, RFI
  ## Matches request patterns designed to traverse filesystem paths, and include
  ## local or remote files

  rule {
    name      = "${var.wafv2_prefix}-detect-rfi-lfi-traversal"
    priority  = 40

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectrfilfitraversal", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }


  ## 5.
  ## OWASP Top 10 A4
  ## Privileged Module Access Restrictions
  ## Restrict access to the admin interface to known source IPs only
  ## Matches the URI prefix, when the remote IP isn't in the whitelist

  rule {
    name      = "${var.wafv2_prefix}-detect-admin-access"
    priority  = 50

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.admin_remote_ipset.arn
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectadminaccess", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 6.
  ## OWASP Top 10 A5
  ## PHP Specific Security Misconfigurations
  ## Matches request patterns designed to exploit insecure PHP/CGI configuration

  rule {
    name      = "${var.wafv2_prefix}-detect-php-insecure"
    priority  = 60

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = "php"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = "/"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "_ENV["
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "auto_append_file="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "disable_functions="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "auto_prepend_file="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "safe_mode="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "_SERVER["
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "allow_url_include="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "open_basedir="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectphpinsecure", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 7.
  ## OWASP Top 10 A7
  ## Mitigate abnormal requests via size restrictions
  ## Enforce consistent request hygene, limit size of key elements

  rule {
    name      = "${var.wafv2_prefix}-restrict-sizes"
    priority  = 70

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 4093

            field_to_match {
              single_query_argument {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }

        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 1024

            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }

        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 512

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}restrictsizes", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 8.
  ## OWASP Top 10 A8
  ## CSRF token enforcement example
  ## Enforce the presence of CSRF token in request header

  rule {
    name      = "${var.wafv2_prefix}-enforce-csrf"
    priority  = 80

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "post"
            
            field_to_match {
              method {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
        statement{
            size_constraint_statement {
                comparison_operator      = "EQ"
                size                     = 36

                field_to_match {
                  single_query_argument {
                    name = var.rule_csrf_header
                  }
                }

                text_transformation {
                  priority = 5
                  type     = "NONE"
                }
            }
          }
        }
      } 

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}enforcecsrf", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 9.
  ## OWASP Top 10 A9
  ## Server-side includes & libraries in webroot
  ## Matches request patterns for webroot objects that shouldn't be directly accessible

  rule {
    name      = "${var.wafv2_prefix}-detect-ssi"
    priority  = 90

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".cfg"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".backup"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".ini"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".conf"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".log"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".bak"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".config"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/includes"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectssi", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  ## 10.
  ## Generic
  ## IP Blacklist
  ## Matches IP addresses that should not be allowed to access content

  rule {
    name      = "${var.wafv2_prefix}-detect-blacklisted-ips"
    priority  = 100

    action {
      block {}
    }

    statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.admin_remote_ipset.arn
          }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}detectblacklistedips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }
}


resource aws_wafv2_ip_set admin_remote_ipset {
  name                              = "${var.wafv2_prefix}-match-admin-remote-ip"
  scope                             = "REGIONAL"
  ip_address_version                = "IPV4"
  addresses                         = var.admin_remote_ipset
}

resource aws_wafv2_ip_set blacklisted_ips {
  name                              = "${var.wafv2_prefix}-match-blacklisted-ips"
  scope                             = "REGIONAL"
  ip_address_version                = "IPV4"
  addresses                         = var.blacklisted_ips
}

resource aws_wafv2_ip_set whitelisted_ips {
  name                              = "${var.wafv2_prefix}-match-whitelisted-ips"
  scope                             = "REGIONAL"
  ip_address_version                = "IPV4"
  addresses                         = var.whitelisted_ips
}

resource aws_wafv2_ip_set whitelisted_elastic_ips {
  name                              = "${var.wafv2_prefix}-match-whitelisted_elastic_ips"
  scope                             = "REGIONAL"
  ip_address_version                = "IPV4"
  addresses                         = var.whitelisted_elastic_ips
}