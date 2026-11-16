package main

import rego.v1

# Security review infra#160 (low): the policy workflow installs semgrep from pip with no
# version pin, and pins actions by tag (@v4), not by commit SHA. A tag can be moved by the
# action's publisher; a 40-hex commit SHA cannot. The risk is highest in a job that can mint
# a cloud credential (`id-token: write`): there a moved tag runs with the deploy identity.

full_sha_pattern := `@[0-9a-f]{40}$`

is_sha_pinned(reference) if {
	regex.match(full_sha_pattern, reference)
}

# hub#495 rule gap A2: a docker:// image is exempt only when it is pinned by digest. A tag such as
# docker://alpine:3.20 can be repointed by the image publisher, and the container step runs inside
# the job, with the job's id-token permission, like any other step.
docker_digest_pattern := `^docker://[^@\s]+@sha256:[0-9a-f]{64}$`

is_digest_pinned_docker(reference) if {
	regex.match(docker_digest_pattern, reference)
}

# A local action or reusable workflow (./...) is this repo's own code, reviewed in the same PR: it
# is not a tag reference to a third-party repo. A local workflow is scanned as its own target, and a
# local composite action's steps are checked when scripts/conftest.sh scans its action.yml (see
# composite_action_steps below).
is_local_reference(reference) if {
	startswith(reference, "./")
}

is_exempt_reference(reference) if {
	is_local_reference(reference)
}

is_exempt_reference(reference) if {
	is_digest_pinned_docker(reference)
}

is_unpinned_reference(reference) if {
	not is_sha_pinned(reference)
	not is_exempt_reference(reference)
}

grants_id_token(permissions) if {
	permissions == "write-all"
}

grants_id_token(permissions) if {
	is_object(permissions)
	object.get(permissions, "id-token", "") == "write"
}

job_can_mint_cloud_token(job) if {
	grants_id_token(object.get(job, "permissions", {}))
}

job_can_mint_cloud_token(job) if {
	not job.permissions
	grants_id_token(object.get(input, "permissions", {}))
}

tag_pinned_steps contains [job_name, reference] if {
	some job_name, job in input.jobs
	some step in object.get(job, "steps", [])
	reference := step.uses
	is_unpinned_reference(reference)
}

# hub#495 rule gap A2: a job that calls a reusable workflow has a job-level `uses:` and no steps.
# The called workflow runs with this job's permissions, so a moved tag there runs with the deploy
# identity too.
tag_pinned_steps contains [job_name, reference] if {
	some job_name, job in input.jobs
	reference := job.uses
	is_string(reference)
	is_unpinned_reference(reference)
}

deny contains msg if {
	some [job_name, reference] in tag_pinned_steps
	job_can_mint_cloud_token(input.jobs[job_name])
	msg := sprintf("Workflow job %q can mint a cloud credential (id-token: write) and runs %q, which is not pinned to a commit SHA (or is a docker:// image without an @sha256: digest). The publisher can move that tag, and the moved code then runs with the deploy identity. Pin it as owner/action@<40-hex sha> # vX, or docker://image@sha256:<digest>.", [job_name, reference])
}

warn contains msg if {
	some [job_name, reference] in tag_pinned_steps
	not job_can_mint_cloud_token(input.jobs[job_name])
	msg := sprintf("Workflow job %q runs %q, which is not pinned to a commit SHA (or is a docker:// image without an @sha256: digest). Pin it as owner/action@<40-hex sha> # vX, or docker://image@sha256:<digest>.", [job_name, reference])
}

# hub#495 rule gap A2: a local composite action (.github/actions/<name>/action.yml, scanned by
# scripts/conftest.sh next to the workflows) declares no permissions of its own. It runs with the
# token of whichever job calls it, which can be a job with id-token: write. So an unpinned `uses:`
# inside it is denied outright, the same as in an id-token job.
composite_action_steps contains reference if {
	runs := object.get(input, "runs", {})
	is_object(runs)
	object.get(runs, "using", "") == "composite"
	some step in object.get(runs, "steps", [])
	reference := step.uses
	is_unpinned_reference(reference)
}

deny contains msg if {
	some reference in composite_action_steps
	msg := sprintf("Composite action runs %q, which is not pinned to a commit SHA (or is a docker:// image without an @sha256: digest). A composite action runs with the token of the job that calls it, which can mint a cloud credential (id-token: write). Pin it as owner/action@<40-hex sha> # vX, or docker://image@sha256:<digest>.", [reference])
}

# hub#495 rule gap A2: a local action is exempt from the SHA pin only because scripts/conftest.sh
# scans its action.yml. That scan covers .github/ only, so a local `uses:` elsewhere
# (`./ci/setup`, `./`, or `./.github/../ci`) would run a composite action that nothing checks.
# Keep local actions under ./.github/.
is_local_reference_outside_scan(reference) if {
	is_local_reference(reference)
	not startswith(reference, "./.github/")
}

is_local_reference_outside_scan(reference) if {
	is_local_reference(reference)
	contains(reference, "..")
}

local_references contains reference if {
	some job in input.jobs
	some step in object.get(job, "steps", [])
	reference := step.uses
	is_string(reference)
}

local_references contains reference if {
	some job in input.jobs
	reference := job.uses
	is_string(reference)
}

local_references contains reference if {
	runs := object.get(input, "runs", {})
	is_object(runs)
	some step in object.get(runs, "steps", [])
	reference := step.uses
	is_string(reference)
}

deny contains msg if {
	some reference in local_references
	is_local_reference_outside_scan(reference)
	msg := sprintf("Local action %q is outside ./.github/. scripts/conftest.sh checks the action.yml of local actions under .github/ only, so the steps of this one are never checked for SHA pins. Move it under ./.github/actions/.", [reference])
}

# pip install <package> with no ==version. `-r file`, `-c file` and options are left out.
pip_install_words contains [job_name, words] if {
	some job_name, job in input.jobs
	some step in object.get(job, "steps", [])
	some line in split(object.get(step, "run", ""), "\n")
	contains(line, "pip install")
	after := split(line, "pip install")[1]
	words := [word | some word in split(trim_space(after), " "); word != ""]
}

unpinned_pip_packages contains [job_name, word] if {
	some [job_name, words] in pip_install_words
	some index, word in words
	not startswith(word, "-")
	not follows_file_option(words, index)
	not contains(word, "==")
	not contains(word, "@")
}

follows_file_option(words, index) if {
	index > 0
	words[index - 1] in {"-r", "--requirement", "-c", "--constraint"}
}

warn contains msg if {
	some [job_name, package_name] in unpinned_pip_packages
	msg := sprintf("Workflow job %q runs `pip install %s` with no version pin. A new release (or a compromised one) changes what CI runs without a PR. Pin it: %s==<version>.", [job_name, package_name, package_name])
}
