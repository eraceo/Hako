package ui

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNO_COLOR_Environment(t *testing.T) {
	origNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	origTerm := os.Getenv("TERM")
	defer func() {
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", origNoColor)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
		_ = os.Setenv("TERM", origTerm)
	}()

	// 1. When NO_COLOR is set to "1"
	_ = os.Setenv("NO_COLOR", "1")
	assert.False(t, IsColorEnabled(os.Stdout.Fd()))
	assert.Equal(t, "test", ColorRed("test"))
	assert.Equal(t, "test", ColorYellow("test"))
	assert.Equal(t, "test", ColorCyan("test"))
	assert.Equal(t, "test", ColorGreen("test"))
	assert.Equal(t, "test", ColorBold("test"))

	// 2. When NO_COLOR is set to empty string ""
	_ = os.Setenv("NO_COLOR", "")
	assert.False(t, IsColorEnabled(os.Stdout.Fd()))
	assert.Equal(t, "test", ColorRed("test"))

	// 3. When TERM is "dumb"
	_ = os.Unsetenv("NO_COLOR")
	_ = os.Setenv("TERM", "dumb")
	assert.False(t, IsColorEnabled(os.Stdout.Fd()))
	assert.Equal(t, "test", ColorRed("test"))
}
