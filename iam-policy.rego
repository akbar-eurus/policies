# iam policy resource must not contain "*"
package main 

deny[msg] {
    policy := input.resource_changes[_]
    policy.type == "aws_iam_policy"
    statement_string := policy.change.after.policy
    parse = json.unmarshal(statement_string)

    statement := parse.Statement[_]
    # statement.Action == "*"
    # statement.Effect == "Allow"
    statement.Resource == "*"

    msg := "Resource '*' is not allowed in policies"
}