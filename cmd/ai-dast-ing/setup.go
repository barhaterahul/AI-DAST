package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/config"
	"github.com/barhaterahul/ai-dast-ing/v4/internal/providers"
	"github.com/barhaterahul/ai-dast-ing/v4/internal/web"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type setupProvider struct {
	id           string
	name         string
	defaultModel string
	needsAPIKey  bool
}

var setupProviders = []setupProvider{
	{id: "openai", name: "OpenAI", defaultModel: "gpt-5.6", needsAPIKey: true},
	{id: "anthropic", name: "Anthropic (Claude)", defaultModel: "claude-fable-5", needsAPIKey: true},
	{id: "google", name: "Google Gemini", defaultModel: "gemini-3.5-flash", needsAPIKey: true},
	{id: "minimax", name: "MiniMax", defaultModel: "MiniMax-M3", needsAPIKey: true},
	{id: "zai", name: "Z.AI (standard API)", defaultModel: "glm-5.3", needsAPIKey: true},
	{id: "zai-coding-plan", name: "Z.AI Coding Plan", defaultModel: "glm-5.3", needsAPIKey: true},
	{id: "ollama", name: "Ollama (local, no API key)", defaultModel: "llama3.3"},
	{id: "custom", name: "Custom OpenAI-compatible endpoint", needsAPIKey: true},
}

type setupPrompter struct {
	in  io.Reader
	buf *bufio.Reader
	out io.Writer
}

func (p *setupPrompter) printf(format string, args ...any) error {
	_, err := fmt.Fprintf(p.out, format, args...)
	return err
}

func (p *setupPrompter) println(args ...any) error {
	_, err := fmt.Fprintln(p.out, args...)
	return err
}

func runSetup(in io.Reader, out io.Writer) (bool, error) {
	path := config.EnvFilePath()
	existing, err := config.ReadEnvFile(path)
	if err != nil {
		return false, err
	}
	p := &setupPrompter{in: in, buf: bufio.NewReader(in), out: out}

	if err := p.println("\nWelcome to AI-DAST-ING setup"); err != nil {
		return false, err
	}
	if err := p.println("Configure an LLM in a few steps. You can change advanced options later in Settings."); err != nil {
		return false, err
	}
	if err := p.println("For best results, choose a current frontier model with strong reasoning and reliable tool calling."); err != nil {
		return false, err
	}
	if err := p.printf("Configuration: %s (saved with mode 0600)\n\n", path); err != nil {
		return false, err
	}

	for i, provider := range setupProviders {
		if err := p.printf("  %d. %s\n", i+1, provider.name); err != nil {
			return false, err
		}
	}
	defaultChoice := setupProviderIndex(existingProvider(existing)) + 1
	choice, err := p.choice("Choose your LLM provider", defaultChoice, len(setupProviders))
	if err != nil {
		return false, err
	}
	selected := setupProviders[choice-1]
	entry, _ := providers.LookupBuiltin(selected.id)

	sameProvider := existingProvider(existing) == selected.id
	modelDefault := selected.defaultModel
	if sameProvider {
		if current := bareSetupModel(existing["AIDASTING_LLM"], selected.id); current != "" {
			modelDefault = current
		}
	}
	model, err := p.required("Model", modelDefault)
	if err != nil {
		return false, err
	}

	apiBase := strings.TrimSpace(entry.BaseURL)
	if sameProvider && strings.TrimSpace(existing["AIDASTING_API_BASE"]) != "" {
		apiBase = strings.TrimSpace(existing["AIDASTING_API_BASE"])
	}
	if selected.id == "custom" || selected.id == "ollama" {
		label := "API base URL"
		if selected.id == "ollama" {
			label = "Ollama URL"
		}
		apiBase, err = p.required(label, apiBase)
		if err != nil {
			return false, err
		}
	}

	apiKey := ""
	if selected.needsAPIKey {
		currentKey := ""
		if sameProvider {
			currentKey = strings.TrimSpace(existing["AIDASTING_API_KEY"])
		}
		apiKey, err = p.secret("API key", currentKey)
		if err != nil {
			return false, err
		}
		if apiKey == "" {
			return false, fmt.Errorf("an API key is required for %s", selected.name)
		}
	}

	updates := map[string]string{
		"AIDASTING_LLM_PROVIDER": selected.id,
		"AIDASTING_LLM":          model,
		"AIDASTING_API_BASE":     apiBase,
		"AIDASTING_API_KEY":      apiKey,
		"AIDASTING_LLM_PROFILE":  "",
	}
	if err := config.UpdateEnvFile(path, updates); err != nil {
		return false, err
	}
	// config.Get may already have been initialized by a transitive package init.
	// Keep the process environment and singleton synchronized so choosing
	// "launch now" uses the values that were just saved without a restart.
	for key, value := range updates {
		if value == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, value)
		}
	}
	cfg := config.Get()
	cfg.LLMProvider = selected.id
	cfg.LLM = model
	cfg.APIBase = apiBase
	cfg.APIKey = apiKey
	cfg.LLMProfile = ""

	if err := p.printf("\n✓ Saved %s with provider %s and model %s.\n", path, selected.name, model); err != nil {
		return false, err
	}
	if err := p.println("  Your API key was not displayed and the file is readable only by your user."); err != nil {
		return false, err
	}
	if err := setupDashboardLogin(p, path, existing); err != nil {
		return false, err
	}
	launch, err := p.yesNo("Start the Web UI now?", true)
	if err != nil {
		return false, err
	}
	if !launch {
		if err := p.println("\nSetup complete. Start later with: ai-dast-ing --web"); err != nil {
			return false, err
		}
	}
	return launch, nil
}

// minDashboardPassword is the shortest operator-chosen dashboard password.
const minDashboardPassword = 8

// setupDashboardLogin configures the dashboard login. The dashboard requires
// one by default (see internal/web/auth_bootstrap.go); this lets the operator
// pick their own instead of using the generated one.
func setupDashboardLogin(p *setupPrompter, path string, existing map[string]string) error {
	if err := p.println("\nDashboard login"); err != nil {
		return err
	}
	user := strings.TrimSpace(existing["AIDASTING_USERNAME"])
	hasPassword := strings.TrimSpace(existing["AIDASTING_PASSWORD_HASH"]) != "" || strings.TrimSpace(existing["AIDASTING_PASSWORD"]) != ""
	if user != "" && hasPassword {
		keep, err := p.yesNo(fmt.Sprintf("Keep the existing dashboard login (user %q)?", user), true)
		if err != nil || keep {
			return err
		}
	}
	if user == "" {
		user = "admin"
	}
	user, err := p.required("Dashboard username", user)
	if err != nil {
		return err
	}

	var password string
	generated := false
	for {
		password, err = p.secret("Dashboard password (Enter to generate one)", "")
		if err != nil {
			return err
		}
		if password == "" {
			if password, err = web.GeneratePassword(); err != nil {
				return err
			}
			generated = true
			break
		}
		if len(password) >= minDashboardPassword {
			break
		}
		if err := p.printf("  Use at least %d characters.\n", minDashboardPassword); err != nil {
			return err
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	updates := map[string]string{
		"AIDASTING_USERNAME":      user,
		"AIDASTING_PASSWORD_HASH": string(hash),
		"AIDASTING_PASSWORD":      "",
	}
	if err := config.UpdateEnvFile(path, updates); err != nil {
		return err
	}
	_ = os.Setenv("AIDASTING_USERNAME", user)
	_ = os.Setenv("AIDASTING_PASSWORD_HASH", string(hash))
	_ = os.Unsetenv("AIDASTING_PASSWORD")
	cfg := config.Get()
	cfg.Username, cfg.PasswordHash, cfg.Password = user, string(hash), ""
	// A one-time password from an earlier first start is now stale.
	web.ClearInitialPassword()

	if generated {
		return p.printf("✓ Dashboard login saved. username: %s  password: %s\n  (shown once — store it in your password manager)\n", user, password)
	}
	return p.printf("✓ Dashboard login saved for user %s (only the bcrypt hash is stored).\n", user)
}

func setupProviderIndex(id string) int {
	for i, provider := range setupProviders {
		if provider.id == id {
			return i
		}
	}
	return 0
}

func existingProvider(values map[string]string) string {
	if provider := strings.ToLower(strings.TrimSpace(values["AIDASTING_LLM_PROVIDER"])); provider != "" {
		return provider
	}
	model := strings.ToLower(strings.TrimSpace(values["AIDASTING_LLM"]))
	if slash := strings.IndexByte(model, '/'); slash > 0 {
		candidate := model[:slash]
		if _, ok := providers.LookupBuiltin(candidate); ok {
			return candidate
		}
	}
	return ""
}

func bareSetupModel(model, provider string) string {
	model = strings.TrimSpace(model)
	prefix := provider + "/"
	if strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix)) {
		return model[len(prefix):]
	}
	return model
}

func (p *setupPrompter) line(label, defaultValue string) (string, error) {
	if defaultValue != "" {
		if err := p.printf("%s [%s]: ", label, defaultValue); err != nil {
			return "", err
		}
	} else if err := p.printf("%s: ", label); err != nil {
		return "", err
	}
	line, err := p.buf.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = defaultValue
	}
	if err == io.EOF && strings.TrimSpace(line) == "" {
		return "", io.ErrUnexpectedEOF
	}
	return value, nil
}

func (p *setupPrompter) required(label, defaultValue string) (string, error) {
	for {
		value, err := p.line(label, defaultValue)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		if err := p.println("  A value is required."); err != nil {
			return "", err
		}
	}
}

func (p *setupPrompter) choice(label string, defaultValue, max int) (int, error) {
	for {
		value, err := p.line(label, strconv.Itoa(defaultValue))
		if err != nil {
			return 0, err
		}
		n, convErr := strconv.Atoi(value)
		if convErr == nil && n >= 1 && n <= max {
			return n, nil
		}
		if err := p.printf("  Enter a number from 1 to %d.\n", max); err != nil {
			return 0, err
		}
	}
}

func (p *setupPrompter) secret(label, existing string) (string, error) {
	if existing != "" {
		if err := p.printf("%s [press Enter to keep the saved key]: ", label); err != nil {
			return "", err
		}
	} else if err := p.printf("%s (input hidden): ", label); err != nil {
		return "", err
	}

	var value string
	if file, ok := p.in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		secret, readErr := term.ReadPassword(int(file.Fd()))
		if err := p.println(); err != nil {
			return "", err
		}
		if readErr != nil {
			return "", readErr
		}
		value = strings.TrimSpace(string(secret))
	} else {
		line, err := p.buf.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		value = strings.TrimSpace(line)
		if err == io.EOF && value == "" && existing == "" {
			return "", io.ErrUnexpectedEOF
		}
	}
	if value == "" {
		return existing, nil
	}
	return value, nil
}

func (p *setupPrompter) yesNo(label string, defaultYes bool) (bool, error) {
	hint := "Y/n"
	if !defaultYes {
		hint = "y/N"
	}
	for {
		if err := p.printf("%s [%s]: ", label, hint); err != nil {
			return false, err
		}
		line, err := p.buf.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		value := strings.ToLower(strings.TrimSpace(line))
		if value == "" {
			if err == io.EOF {
				return false, io.ErrUnexpectedEOF
			}
			return defaultYes, nil
		}
		switch value {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			if err := p.println("  Enter y or n."); err != nil {
				return false, err
			}
		}
	}
}
