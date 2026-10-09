---
page_title: 'forge_llm_gateway_experiment Resource - Forge'
subcategory: 'LLM Gateway'
description: |-
  Mirror or compare sampled LLM Gateway requests with a candidate route.
---

# forge_llm_gateway_experiment (Resource)

An experiment samples live requests on one access profile and sends a candidate request through Forge policy and budget checks. Candidate calls have separate usage and spend evidence. The live response is unchanged. Results are available in the Console Experiments tab and the API.

```terraform
resource "forge_llm_gateway_experiment" "candidate" {
  name               = "New model trial"
  access_profile_id  = forge_llm_gateway_access_profile.production.id
  candidate_route_id = "lgwr_candidate"
  mode               = "mirror"
  sample_percent     = 10
  spend_cap_usd      = 10
  end_at             = "2026-10-10T18:00:00Z"
  state              = "active"
}
```

For Compare, set `mode = "compare"` and `judge_route_id` to a route in the same profile. Forge uses the built-in `answer_preference` rubric, version 1. The same `spend_cap_usd` covers candidate and judge requests, with separate token and cost evidence in results. Streaming requests are mirrored but their comparison is skipped until finalized primary text is available.

`state` accepts `active`, `paused`, or `stopped`. Deleting the Terraform resource stops the experiment while preserving its usage and audit records. The candidate and judge routes must belong to an active access profile and support Chat Completions, Responses, or Anthropic Messages. If pricing cannot establish a spend upper bound, the sample or comparison is skipped. Unknown actual cost pauses further sampling until reconciled.
