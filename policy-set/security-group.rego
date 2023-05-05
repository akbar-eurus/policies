package main
# Check security grou embedded ingress rule 
deny[msg]{
    security_group := input.resource_changes[_]
    security_group.type == "aws_security_group"
    ingress_rule := security_group.change.after.ingress[_].cidr_blocks[_]
    ingress_rule == "0.0.0.0/0"

    msg := "Inbound rule all is not allowed"
}

# Checks security groups rules
deny[reason] {
  r := tfplan.resource_changes[_]
  r.type == "aws_security_group_rule"
  invalid := invalid_cidrs[_]
  array_contains(r.change.after.cidr_blocks,invalid)
  reason := sprintf(
              "%-40s :: security group rule invalid  CIDR %s",
              [r.address,invalid]
            )
}