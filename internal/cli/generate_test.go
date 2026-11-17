package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/entropy"
)

type generateTestCase struct {
	name             string
	args             []string
	expectedContains []string
	expectedError    string
}

func getGenerateCmdTestCases() []generateTestCase {
	return []generateTestCase{
		{
			name: "Generate standard password (16 chars, symbols)",
			args: []string{"gen"}, // "gen" is the alias for "generate"
			expectedContains: []string{
				"Password strength:",
				"bits of entropy",
			},
		},
		{
			name: "Generate very long password",
			args: []string{"gen", "--length=64"},
			expectedContains: []string{
				"Very Strong", // 64 chars will definitely hit the Very Strong threshold
			},
		},
		{
			name: "Generate memorable password",
			args: []string{"gen", "--memorable"},
			expectedContains: []string{
				"Password strength:",
			},
		},
		{
			name: "Generate without symbols",
			args: []string{"gen", "--no-symbols"},
			expectedContains: []string{
				"Password strength:",
			},
		},
		{
			name: "Generate without similar characters",
			args: []string{"gen", "--no-similar"},
			expectedContains: []string{
				"Password strength:",
			},
		},
		{
			name:          "Fails on too short length",
			args:          []string{"gen", "--length=4"},
			expectedError: "password length must be at least",
		},
		{
			name:          "Fails on too long length",
			args:          []string{"gen", "--length=200"},
			expectedError: "password length cannot exceed 128",
		},
		{
			name: "Generate memorable password with custom valid word count",
			args: []string{"gen", "--memorable", "--length=4"},
			expectedContains: []string{
				"Password strength:",
			},
		},
		{
			name:          "Fails when memorable length exceeds 10 words",
			args:          []string{"gen", "--memorable", "--length=11"},
			expectedError: "memorable password word count must be between 3 and 10",
		},
		{
			name:          "Fails when memorable length below 3 words",
			args:          []string{"gen", "--memorable", "--length=2"},
			expectedError: "memorable password word count must be between 3 and 10",
		},
	}
}

func TestGenerateCmd(t *testing.T) {
	tests := getGenerateCmdTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare strict arguments
			// We don't need to reset global flags anymore because executeCommandWithMocks
			// creates a fresh command tree for every test.
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--keyfile=none") // Always bypass local keyfile configs

			// Execute target command with strictly mocked I/O
			// No Stdin ("") needed since generation is non-interactive
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, "")

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}
			require.NoError(t, err)

			for _, expected := range tt.expectedContains {
				assert.Contains(t, actualOutput, expected)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Unit Tests for Entropy and Character Analysis (Zero-Allocation verified)
// -----------------------------------------------------------------------------

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name        string
		password    []byte
		minExpected float64
		maxExpected float64
	}{
		{
			name:        "Empty password",
			password:    []byte(""),
			minExpected: 0,
			maxExpected: 0,
		},
		{
			name:     "Only numbers (10^8)",
			password: []byte("12345678"),
			// Pool = 10, Length = 8 -> 8 * log2(10) ≈ 26.57
			minExpected: 26.0,
			maxExpected: 27.0,
		},
		{
			name:     "Lower case only (26^8 with repetition penalty)",
			password: []byte("password"),
			// EffectiveLength = (8+7)/2 = 7.5, Pool = 26 -> 7.5 * log2(26) ≈ 35.25
			minExpected: 35.0,
			maxExpected: 35.5,
		},
		{
			name:     "Mixed complex (94^16 with repetition penalty)",
			password: []byte("P@ssw0rd_Secur3!"),
			// EffectiveLength = (16+14)/2 = 15, Pool = 94 -> 15 * log2(94) ≈ 98.32
			minExpected: 98.0,
			maxExpected: 98.7,
		},
		{
			name:     "Unicode password",
			password: []byte("🔒MotDePasse123!"),
			// Adjusted entropy with repetition penalty ≈ 91.77
			minExpected: 91.0,
			maxExpected: 92.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropyBits := entropy.Calculate(tt.password)
			assert.GreaterOrEqual(t, entropyBits, tt.minExpected)
			assert.LessOrEqual(t, entropyBits, tt.maxExpected)
		})
	}
}
