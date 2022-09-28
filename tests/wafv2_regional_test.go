package test

import (
	"fmt"
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func Testwafv2regionalRequiresInput(t *testing.T) {

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../modules/wafv2-regional",
	})

	_, err := terraform.InitAndApplyE(t, terraformOptions)

	assert.Error(t, err)
}

func Testwafv2regional(t *testing.T) {

	var name string = "bgaugerqri"

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../modules/wafv2-regional",
		Vars: map[string]interface{}{
			"text": name,
		},
	})

	defer terraform.Destroy(t, terraformOptions)

	terraform.InitAndApply(t, terraformOptions)

	output := terraform.Output(t, terraformOptions, "result")

	expectedOutput := fmt.Sprintf("%s!", name)

	assert.Equal(t, expectedOutput, output)
}
