package wrappers

type PolicyResponseModel struct {
	Status     string   `json:"status"`
	BreakBuild bool     `json:"breakBuild"`
	Policies   []Policy `json:"policies"`
}

type Policy struct {
	Name          string   `json:"policyName"`
	BreakBuild    bool     `json:"breakBuild"`
	Status        string   `json:"status"`
	Description   string   `json:"description"`
	RulesViolated []string `json:"rulesViolated"`
	Tags          []string `json:"tags"`
}

type PrPolicy struct {
	Name       string      `json:"policyName"`
	RulesNames []string    `json:"rulesNames"`
	BreakBuild bool        `json:"breakBuild"`
	Findings   []PrFinding `json:"findings"`
}

type PrFinding struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	State        string `json:"state"`
	SimilarityID string `json:"similarityId"`
}

type PolicyWrapper interface {
	EvaluatePolicy(map[string]string) (*PolicyResponseModel, *WebError, error)
}
