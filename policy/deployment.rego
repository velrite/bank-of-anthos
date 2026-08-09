package main

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.containers[_].resources.limits
    msg := "Deployment must set resource limits (CPU/memory) on every container"
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.runAsNonRoot != true
    msg := sprintf("Container '%s' must set runAsNonRoot: true", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%s' must not use the ':latest' tag - use a pinned version or commit SHA", [container.name])
}
