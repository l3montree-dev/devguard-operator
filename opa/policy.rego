package kubernetes.admission


# Deny if the Pod doesn't specify an image digest in every container.
deny[{"msg": msg }] if {
    input.request.kind.kind == "Pod"

    msg := "All containers must use an image pinned by digest (sha256)."
    # Check each container in the pod:
    every container in input.request.object.spec.containers {
        # If there's no @sha256: in the container.image, deny.
        not regex.match(".*@sha256:[0-9a-fA-F]{64}", container.image)
        msg = sprintf("%q, Container %q must use an image pinned by digest (sha256).", [msg, container.name])
    }
}

# Deny if the HTTP GET call fails or returns non-200 status.
deny[{"msg": msg }] if {
    input.request.kind.kind == "Pod"
    msg := "HTTP check failed for one or more containers."
    every container in input.request.object.spec.containers { 
        # Extract the sha from the image reference:
        regex.match(".*@sha256:(?<sha>[0-9a-fA-F]{64})", container.image, groups)
        sha := groups.sha

        # Make an HTTP GET request (experimental!). Replace with your actual endpoint.
        resp := http.send({
            "method": "GET",
            "url": sprintf("https://api.main.devguard.org/verify-supply-chain?digest=%s", [sha]),
        })

        # You can check resp.body or resp.status as needed
        resp.status != 200
        msg = sprintf("%q, Container %q failed the HTTP check.", [msg, container.name])
  }
}