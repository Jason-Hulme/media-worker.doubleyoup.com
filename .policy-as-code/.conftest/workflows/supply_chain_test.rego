package main

import rego.v1

deploy_job_with(reference) := {"jobs": {"deploy": {
	"permissions": {"contents": "read", "id-token": "write"},
	"steps": [{"uses": reference}],
}}}

test_tag_pinned_action_in_id_token_job_is_denied if {
	count(deny) > 0 with input as deploy_job_with("google-github-actions/auth@v2")
}

test_sha_pinned_action_in_id_token_job_passes if {
	count(deny) == 0 with input as deploy_job_with("google-github-actions/auth@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f")
}

test_workflow_level_id_token_counts if {
	count(deny) > 0 with input as {
		"permissions": {"id-token": "write"},
		"jobs": {"deploy": {"steps": [{"uses": "google-github-actions/setup-gcloud@v2"}]}},
	}
}

test_tag_pinned_action_without_id_token_only_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"uses": "actions/checkout@v4"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_local_action_is_not_flagged if {
	policy_input := {"jobs": {"build": {"permissions": {"id-token": "write"}, "steps": [{"uses": "./.github/actions/setup"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

test_unpinned_pip_install_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep"}]}}}
	count(warn) > 0 with input as policy_input
}

test_pinned_pip_install_passes if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep==1.97.0\npip install -r requirements.txt"}]}}}
	count(warn) == 0 with input as policy_input
}

# ── hub#495 rule gap A2 ──────────────────────────────────────────────────────────────────────

test_reusable_workflow_tag_in_id_token_job_is_denied if {
	count(deny) > 0 with input as {"jobs": {"deploy": {"permissions": {"id-token": "write"}, "uses": "org/repo/.github/workflows/d.yml@v1"}}}
}

test_reusable_workflow_tag_without_id_token_warns if {
	policy_input := {"jobs": {"call": {"permissions": {"contents": "read"}, "uses": "org/repo/.github/workflows/d.yml@main"}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_sha_pinned_reusable_workflow_passes if {
	policy_input := {"jobs": {"deploy": {"permissions": {"id-token": "write"}, "uses": "org/repo/.github/workflows/d.yml@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f"}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

test_local_reusable_workflow_is_not_flagged if {
	policy_input := {"jobs": {"deploy": {"permissions": {"id-token": "write"}, "uses": "./.github/workflows/deploy-steps.yml"}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

test_mutable_docker_tag_in_id_token_job_is_denied if {
	count(deny) > 0 with input as deploy_job_with("docker://alpine:latest")
}

test_mutable_docker_tag_without_id_token_warns if {
	policy_input := {"jobs": {"p": {"permissions": {"contents": "read"}, "steps": [{"uses": "docker://alpine:3.20"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_digest_pinned_docker_in_id_token_job_passes if {
	reference := "docker://alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
	count(deny) == 0 with input as deploy_job_with(reference)
	count(warn) == 0 with input as deploy_job_with(reference)
}

test_docker_tag_with_a_short_digest_is_denied if {
	count(deny) > 0 with input as deploy_job_with("docker://alpine:3.20@sha256:short")
}

test_tag_pinned_step_in_a_composite_action_is_denied if {
	msgs := deny with input as {"name": "setup", "runs": {"using": "composite", "steps": [{"uses": "actions/setup-node@v4"}]}}
	some msg in msgs
	contains(msg, "Composite action runs \"actions/setup-node@v4\"")
}

test_mutable_docker_step_in_a_composite_action_is_denied if {
	msgs := deny with input as {"runs": {"using": "composite", "steps": [{"uses": "docker://alpine:latest"}]}}
	some msg in msgs
	contains(msg, "Composite action runs \"docker://alpine:latest\"")
}

test_pinned_composite_action_passes if {
	count(deny) == 0 with input as {"runs": {"using": "composite", "steps": [
		{"uses": "actions/setup-node@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f"},
		{"uses": "./.github/actions/other"},
		{"run": "echo hi", "shell": "bash"},
	]}}
}

test_a_javascript_action_metadata_file_is_not_a_composite if {
	count(deny) == 0 with input as {"runs": {"using": "node20", "main": "index.js"}}
}

test_local_action_outside_github_folder_is_denied if {
	msgs := deny with input as {"jobs": {"build": {"steps": [{"uses": "./ci/setup"}]}}}
	some msg in msgs
	contains(msg, "Local action \"./ci/setup\" is outside ./.github/")
}

test_local_action_escaping_github_folder_is_denied if {
	msgs := deny with input as {"jobs": {"build": {"steps": [{"uses": "./.github/../ci/setup"}]}}}
	some msg in msgs
	contains(msg, "is outside ./.github/")
}

test_root_local_action_in_a_composite_action_is_denied if {
	msgs := deny with input as {"runs": {"using": "composite", "steps": [{"uses": "./"}]}}
	some msg in msgs
	contains(msg, "Local action \"./\" is outside ./.github/")
}

test_nested_local_action_under_github_folder_passes if {
	deploy_job := {"jobs": {"deploy": {
		"permissions": {"id-token": "write"},
		"steps": [{"uses": "./.github/actions/deploy/gcp"}],
	}}}
	count(deny) == 0 with input as deploy_job
	count(warn) == 0 with input as deploy_job
}
