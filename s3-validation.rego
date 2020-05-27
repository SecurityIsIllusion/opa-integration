package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################

# acceptable score for automated authorization
blast_radius = 5

# weights assigned for each operation on each resource-type
weights = {
    "aws_autoscaling_group": {"delete": 100, "create": 10, "modify": 1},
    "aws_s3_bucket": {"acl": 10, "ssl": 10, "logs": 5, "sse": 10, "tags": 10, "region":10, "logging":10, "name":10}
}

# Consider exactly these resource types in calculations
resource_types = {"aws_s3_bucket"}

minimum_tags = {"Name", "app:name"}

violations = data.terraform.analysis.violation
authorized = data.terraform.analysis.authz


#########
# Policy
#########

# Authorization holds if score for the plan is acceptable and no changes are made to IAM
default authz = false
authz {
    score < blast_radius
    not touches_iam
}

# Compute the score for a Terraform plan as the weighted sum of deletions, creations, modifications
score = s {
    all := [ x |
            some resource_type
            crud := weights[resource_type];
            acl_chg := crud["acl"] * s3_acl_change[resource_type];
            region_chg := crud["region"] * s3_region_change[resource_type];
            sse_chg := crud["sse"] * s3_encryption_change[resource_type];
            tags_chg := crud["tags"] * s3_tags_change[resource_type];
            logging_chg := crud["logging"] * s3_logging_change[resource_type];
            name := crud["name"] * s3_name_change[resource_type];
            x := acl_chg + region_chg + sse_chg + tags_chg + logging_chg + name
    ]
    s := sum(all)
}

# Whether there is any change to IAM
touches_iam {
    all := resources["aws_iam"]
    count(all) > 0
}


# Whether there is any change to IAM
touches_sg {
    all := resources["aws_security_group"]
    count(all) > 0
}

####################
# Terraform Library
####################

# list of all resources of a given type
resources[resource_type] = all {
    some resource_type
    resource_types[resource_type]
    all := [name |
        name:= tfplan.resource_changes[_]
        name.type == resource_type
    ]
}


#print validation errors to console

violation["missing required tags"] {
   s3_tags_change[resource_types[_]] > 0
}

#violation["bucket region shoule be in eu-central-1"] {
#   s3_region_change[resource_types[_]] > 0
#}

#violation["bucket acl property should be private unless it is a website bucket "] {
#   s3_acl_change[resource_types[_]] > 0
#}

violation["bucket should be encrypted with AES256/KMS "] {
   s3_encryption_change[resource_types[_]] > 0
}

violation["bucket logging should be enabled "] {
   s3_logging_change[resource_types[_]] > 0
}

violation["bucket name should start with my- "] {
   s3_name_change[resource_types[_]] > 0
}


# Validte each compliance rule.

# Enforce S3 bucket region to eu-central-1
s3_region_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    creates := [res |  res:= all[_]; res.change.after.region != "us-east-1"]
    num := count(creates)
}

# S3 bucket name should match a given pattern. - regex.
s3_name_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; not is_proper_name(res.change.after.bucket)]
    num := count(modifies)
}


# S3 acl property , bucket ACL can't be public unless its is a website hosting bucket.
#s3_acl_change[resource_type] = num {
#    some resource_type
#    resource_types[resource_type]
#    all := resources[resource_type]
#    modifies := [res |  res:= all[_]; res.change.after.acl == "public"; res.change.after.website != null]
#    num := count(modifies)
#}

# S3 Excryption , should be either AES256 or KMS
s3_encryption_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    #check if encryption is used. 
    modifies := [res |  res:= all[_]; not res.change.after.server_side_encryption_configuration[0].rule] 
    # check for specific type of encryption
    #modifies := [res |  res:= all[_]; res.change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != "AES256"; 
    #            res.change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != "aws:kms"]
    num := count(modifies)
    trace("Hello There!")
}

# S3 missing tags - refer to variable minimum_tags
s3_tags_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; not tags_contain_proper_keys(res.change.after.tags)]
    num := count(modifies)
}

# S3 logging should be enabled.
s3_logging_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; not res.change.after.logging[0].target_bucket] 
    num := count(modifies)
}

#helper functions 
tags_contain_proper_keys(tags) {
    keys := {key | tags[key]}
    leftover := minimum_tags - keys
    leftover == set()
}

contains(arr, elem) {
  arr[_] = elem
}

is_proper_name(name) {
    re_match(`my-?[a-zA-Z0-9()]`, name)
}
