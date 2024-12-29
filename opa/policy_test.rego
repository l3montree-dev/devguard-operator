package kubernetes.admission_test

import data.kubernetes.admission

#
# Mock data for HTTP calls
#
mock_success := {
  "status": 200,
  "body": {"message": "OK"}
}

mock_fail := {
  "status": 404,
  "body": {"error": "Not Found"}
}

#
# We define mock rules that *override* http.send in tests.
#
http_send_mock_success(_args) = mock_success if {
  true
}

http_send_mock_fail(_args) = mock_fail if {
  true
}

################################################################################
# TEST 1: Deny if container image is missing @sha256
################################################################################
test_deny_no_digest if {
  # Build an input that has no SHA in the container image.
  example_request := {
    "request": {
      "kind": {
        "kind": "Pod"
      },
      "object": {
        "spec": {
          "containers": [
            {
              "name": "app",
              "image": "my-registry/my-app:latest"  # no @sha256 here
            }
          ]
        }
      }
    }
  }

  # Evaluate policy.deny with the test input
  admission.deny
    with input as example_request
    with http.send as http_send_mock_success
}

################################################################################
# TEST 2: Deny if digest is present but HTTP check fails (non-200)
################################################################################
test_deny_digest_http_fail if {
  # Build an input that has a valid SHA
  example_request := {
    "request": {
      "kind": {
        "kind": "Pod"
      },
      "object": {
        "spec": {
          "containers": [
            {
              "name": "app",
              "image": "my-registry/my-app@sha256:123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234"
            }
          ]
        }
      }
    }
  }

  admission.deny
    with input as example_request
    with http.send as http_send_mock_fail
}

################################################################################
# TEST 3: Allow if digest is present and HTTP check returns 200
################################################################################
test_allow_digest_http_ok if {
  # Build an input that has a valid SHA
  example_request := {
    "request": {
      "kind": {
        "kind": "Pod"
      },
      "object": {
        "spec": {
          "containers": [
            {
              "name": "app",
              "image": "my-registry/my-app@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
            }
          ]
        }
      }
    }
  }

  not admission.deny
    with input as example_request
    with http.send as http_send_mock_success
}
