package util

import (
	"testing"

	"github.com/checkmarx/ast-cli/internal/wrappers"
	"github.com/checkmarx/ast-cli/internal/wrappers/mock"
	asserts "github.com/stretchr/testify/assert"

	"gotest.tools/assert"
)

const (
	token = "token"
)

func TestNewGithubPRDecorationCommandMustExist(t *testing.T) {
	cmd := PRDecorationGithub(nil, nil, nil, nil)
	assert.Assert(t, cmd != nil, "PR decoration command must exist")

	err := cmd.Execute()
	assert.ErrorContains(t, err, "scan-id")
}

func TestNewGitlabMRDecorationCommandMustExist(t *testing.T) {
	cmd := PRDecorationGitlab(nil, nil, nil, nil)
	assert.Assert(t, cmd != nil, "MR decoration command must exist")

	err := cmd.Execute()
	assert.ErrorContains(t, err, "scan-id")
}

func TestNewAzurePRDecorationCommandMustExist(t *testing.T) {
	cmd := PRDecorationAzure(nil, nil, nil, nil)
	assert.Assert(t, cmd != nil, "PR decoration command must exist")

	err := cmd.Execute()
	assert.ErrorContains(t, err, "scan-id")
}

func TestIsScanRunning_WhenScanRunning_ShouldReturnTrue(t *testing.T) {
	scansMockWrapper := &mock.ScansMockWrapper{Running: true}

	scanRunning, _ := IsScanRunningOrQueued(scansMockWrapper, "ScanRunning")
	asserts.True(t, scanRunning)
}

func TestIsScanRunning_WhenScanDone_ShouldReturnFalse(t *testing.T) {
	scansMockWrapper := &mock.ScansMockWrapper{Running: false}

	scanRunning, _ := IsScanRunningOrQueued(scansMockWrapper, "ScanNotRunning")
	asserts.False(t, scanRunning)
}

func TestPRDecorationGithub_WhenNoViolatedPolicies_ShouldNotReturnPolicy(t *testing.T) {
	prMockWrapper := &mock.PolicyMockWrapper{}
	policyResponse, _, _ := prMockWrapper.EvaluatePolicy(nil)
	prPolicy := policiesToPrPolicies(policyResponse, nil)
	asserts.True(t, len(prPolicy) == 0)
}

func TestPoliciesToPrPolicies_WhenViolatedPoliciesWithMatchingFindings_ShouldIncludeFindings(t *testing.T) {
	policyWrapper := &mock.PolicyMockWrapper{ViolatedRules: []string{"mock-query-name-1"}}
	policyResponse, _, _ := policyWrapper.EvaluatePolicy(nil)

	scanResults := &wrappers.ScanResultsCollection{
		Results: []*wrappers.ScanResult{
			{
				ID:           "finding-1",
				Type:         "sast",
				Severity:     "high",
				State:        "TO_VERIFY",
				SimilarityID: "sim-1",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "mock-query-name-1",
				},
			},
			{
				ID:           "finding-2",
				Type:         "sast",
				Severity:     "medium",
				State:        "TO_VERIFY",
				SimilarityID: "sim-2",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "other-rule",
				},
			},
		},
	}

	prPolicies := policiesToPrPolicies(policyResponse, scanResults)

	asserts.Equal(t, 1, len(prPolicies))
	asserts.Equal(t, "MOCK_NAME", prPolicies[0].Name)
	asserts.Equal(t, 1, len(prPolicies[0].Findings))
	asserts.Equal(t, "finding-1", prPolicies[0].Findings[0].ID)
	asserts.Equal(t, "sast", prPolicies[0].Findings[0].Type)
	asserts.Equal(t, "high", prPolicies[0].Findings[0].Severity)
	asserts.Equal(t, "TO_VERIFY", prPolicies[0].Findings[0].State)
	asserts.Equal(t, "sim-1", prPolicies[0].Findings[0].SimilarityID)
}

func TestPoliciesToPrPolicies_WhenViolatedPoliciesWithNoMatchingFindings_ShouldReturnEmptyFindings(t *testing.T) {
	policyWrapper := &mock.PolicyMockWrapper{ViolatedRules: []string{"some-rule"}}
	policyResponse, _, _ := policyWrapper.EvaluatePolicy(nil)

	scanResults := &wrappers.ScanResultsCollection{
		Results: []*wrappers.ScanResult{
			{
				ID:       "finding-1",
				Type:     "sast",
				Severity: "high",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "different-rule",
				},
			},
		},
	}

	prPolicies := policiesToPrPolicies(policyResponse, scanResults)

	asserts.Equal(t, 1, len(prPolicies))
	asserts.Equal(t, 0, len(prPolicies[0].Findings))
}

func TestPoliciesToPrPolicies_WhenNilScanResults_ShouldReturnEmptyFindings(t *testing.T) {
	policyWrapper := &mock.PolicyMockWrapper{ViolatedRules: []string{"some-rule"}}
	policyResponse, _, _ := policyWrapper.EvaluatePolicy(nil)

	prPolicies := policiesToPrPolicies(policyResponse, nil)

	asserts.Equal(t, 1, len(prPolicies))
	asserts.Equal(t, 0, len(prPolicies[0].Findings))
}

func TestBuildFindingsByRuleMap_WhenNilResults_ShouldReturnEmptyMap(t *testing.T) {
	result := buildFindingsByRuleMap(nil)
	asserts.Equal(t, 0, len(result))
}

func TestBuildFindingsByRuleMap_WhenResultsWithQueryNames_ShouldGroupByRule(t *testing.T) {
	scanResults := &wrappers.ScanResultsCollection{
		Results: []*wrappers.ScanResult{
			{
				ID:       "1",
				Type:     "sast",
				Severity: "high",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "rule-a",
				},
			},
			{
				ID:       "2",
				Type:     "sast",
				Severity: "medium",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "rule-a",
				},
			},
			{
				ID:       "3",
				Type:     "sca",
				Severity: "low",
				ScanResultData: wrappers.ScanResultData{
					QueryName: "rule-b",
				},
			},
		},
	}

	result := buildFindingsByRuleMap(scanResults)

	asserts.Equal(t, 2, len(result))
	asserts.Equal(t, 2, len(result["rule-a"]))
	asserts.Equal(t, 1, len(result["rule-b"]))
}

func TestUpdateAPIURLForGithubOnPrem_whenAPIURLIsSet_ShouldUpdateAPIURL(t *testing.T) {
	selfHostedURL := "https://github.example.com"
	updatedAPIURL := updateAPIURLForGithubOnPrem(selfHostedURL)
	asserts.Equal(t, selfHostedURL+githubOnPremURLSuffix, updatedAPIURL)
}

func TestUpdateAPIURLForGithubOnPrem_whenAPIURLIsNotSet_ShouldReturnCloudAPIURL(t *testing.T) {
	cloudAPIURL := updateAPIURLForGithubOnPrem("")
	asserts.Equal(t, githubCloudURL, cloudAPIURL)
}

func TestUpdateAPIURLForGitlabOnPrem_whenAPIURLIsSet_ShouldUpdateAPIURL(t *testing.T) {
	selfHostedURL := "https://gitlab.example.com"
	updatedAPIURL := updateAPIURLForGitlabOnPrem(selfHostedURL)
	asserts.Equal(t, selfHostedURL+gitlabOnPremURLSuffix, updatedAPIURL)
}

func TestUpdateAPIURLForGitlabOnPrem_whenAPIURLIsNotSet_ShouldReturnCloudAPIURL(t *testing.T) {
	cloudAPIURL := updateAPIURLForGitlabOnPrem("")
	asserts.Equal(t, gitlabCloudURL, cloudAPIURL)
}

func TestCheckIsCloudAndValidateFlag(t *testing.T) {
	tests := []struct {
		name          string
		apiURL        string
		namespaceFlag string
		projectKey    string
		expectedCloud bool
		expectedError string
	}{
		{
			name:          "Bitbucket Cloud",
			apiURL:        "",
			namespaceFlag: "namespace",
			projectKey:    "",
			expectedCloud: true,
			expectedError: "",
		},
		{
			name:          "Bitbucket Cloud without https",
			apiURL:        "bitbucket.org",
			namespaceFlag: "namespace",
			projectKey:    "",
			expectedCloud: true,
			expectedError: "",
		},
		{
			name:          "Bitbucket Cloud with namespace",
			apiURL:        "https://bitbucket.org",
			namespaceFlag: "namespace",
			projectKey:    "",
			expectedCloud: true,
			expectedError: "",
		},
		{
			name:          "Bitbucket Cloud without namespace",
			apiURL:        "https://bitbucket.org",
			namespaceFlag: "",
			projectKey:    "",
			expectedCloud: true,
			expectedError: "namespace is required for Bitbucket Cloud",
		},
		{
			name:          "Bitbucket Server with project key and API URL",
			apiURL:        "https://bitbucket.example.com",
			namespaceFlag: "",
			projectKey:    "projectKey",
			expectedCloud: false,
			expectedError: "",
		},
		{
			name:          "Bitbucket Server without project key",
			apiURL:        "https://bitbucket.example.com",
			namespaceFlag: "",
			projectKey:    "",
			expectedCloud: false,
			expectedError: "project key is required for Bitbucket Server",
		},
		{
			name:          "Bitbucket Cloud with URL and project key",
			apiURL:        "https://bitbucket.org",
			namespaceFlag: "",
			projectKey:    "projectKey",
			expectedCloud: true,
			expectedError: "namespace is required for Bitbucket Cloud",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			isCloud, err := checkIsCloudAndValidateFlag(tt.apiURL, tt.namespaceFlag, tt.projectKey)
			asserts.Equal(t, tt.expectedCloud, isCloud)
			if tt.expectedError != "" {
				asserts.EqualError(t, err, tt.expectedError)
			} else {
				asserts.NoError(t, err)
			}
		})
	}
}

func TestRepoSlugFormatBB(t *testing.T) {
	tests := []struct {
		name         string
		repoNameFlag string
		expectedSlug string
	}{
		{
			name:         "Single word repo name",
			repoNameFlag: "repository",
			expectedSlug: "repository",
		},
		{
			name:         "Repo name with spaces",
			repoNameFlag: "my repository",
			expectedSlug: "my-repository",
		},
		{
			name:         "Repo name with multiple spaces",
			repoNameFlag: "my awesome repository",
			expectedSlug: "my-awesome-repository",
		},
		{
			name:         "Repo name with leading and trailing spaces",
			repoNameFlag: " my repository ",
			expectedSlug: "my-repository",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			slug := formatRepoNameSlugBB(tt.repoNameFlag)
			asserts.Equal(t, tt.expectedSlug, slug)
		})
	}
}

func TestGetAzureAPIURL_whenAPIURLIsSet_ShouldUpdateAPIURL(t *testing.T) {
	selfHostedURL := "https://azure.example.com"
	updatedAPIURL := getAzureAPIURL(selfHostedURL)
	asserts.Equal(t, selfHostedURL, updatedAPIURL)
}

func TestGetAzureAPIURL_whenAPIURLIsNotSet_ShouldReturnCloudAPIURL(t *testing.T) {
	cloudAPIURL := getAzureAPIURL("")
	asserts.Equal(t, azureCloudURL, cloudAPIURL)
}

func TestUpdateScmTokenForAzureOnPrem_whenUserNameIsSet_ShouldUpdateToken(t *testing.T) {
	username := "username"
	expectedToken := username + ":" + token
	updatedToken := updateScmTokenForAzure(token, username)
	asserts.Equal(t, expectedToken, updatedToken)
}

func TestUpdateScmTokenForAzureOnPrem_whenUserNameNotSet_ShouldNotUpdateToken(t *testing.T) {
	username := ""
	expectedToken := token
	updatedToken := updateScmTokenForAzure(token, username)
	asserts.Equal(t, expectedToken, updatedToken)
}

func TestCreateAzureNameSpace_ShouldCreateNamespace(t *testing.T) {
	azureNamespace := createAzureNameSpace("organization", "project")
	asserts.Equal(t, "organization/project", azureNamespace)
}

func TestValidateAzureOnPremParameters_WhenParametersAreValid_ShouldReturnNil(t *testing.T) {
	err := validateAzureOnPremParameters("https://azure.example.com", "username")
	asserts.Nil(t, err)
}

func TestValidateAzureOnPremParameters_WhenParametersAreNotValid_ShouldReturnError(t *testing.T) {
	err := validateAzureOnPremParameters("", "username")
	asserts.NotNil(t, err)
}
