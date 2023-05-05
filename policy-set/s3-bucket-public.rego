#s3 bucket must not be public
package main

deny[msg] {
    public_s3 := input.resource_changes[_]
    public_read := public_s3.change.after.acl
    public_read == "public-read"

    msg := "public bucket is not allowed"
}