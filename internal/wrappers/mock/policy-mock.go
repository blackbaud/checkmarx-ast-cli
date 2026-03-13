package mock

import "github.com/checkmarx/ast-cli/internal/wrappers"

type PolicyMockWrapper struct {
	ViolatedRules []string
}

func (r *PolicyMockWrapper) EvaluatePolicy(params map[string]string) (
	*wrappers.PolicyResponseModel,
	*wrappers.WebError,
	error,
) {
	policyResponseModel := wrappers.PolicyResponseModel{}
	policyResponseModel.BreakBuild = false
	policyResponseModel.Status = "COMPLETED"

	policy := wrappers.Policy{}
	policy.Name = "MOCK_NAME"
	policy.RulesViolated = r.ViolatedRules
	policy.BreakBuild = false
	policy.Description = "MOCK_DESC"
	policy.Tags = make([]string, 0)

	var policies []wrappers.Policy
	policies = append(policies, policy)
	policyResponseModel.Policies = policies

	return &policyResponseModel, nil, nil
}
