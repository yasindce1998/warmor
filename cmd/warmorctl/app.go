package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type view int

const (
	viewDashboard view = iota
	viewAgents
	viewPolicies
	viewRollouts
	viewCerts
)

type app struct {
	serverURL   string
	token       string
	currentView view
	width       int
	height      int

	dashboard *dashboardModel
	agents    *agentsModel
	policies  *policiesModel
	rollouts  *rolloutsModel
	certs     *certsModel

	err error
}

func newApp(serverURL, token string) *app {
	return &app{
		serverURL: serverURL,
		token:     token,
		dashboard: newDashboardModel(serverURL, token),
		agents:    newAgentsModel(serverURL, token),
		policies:  newPoliciesModel(serverURL, token),
		rollouts:  newRolloutsModel(serverURL, token),
		certs:     newCertsModel(),
	}
}

func (a *app) Init() tea.Cmd {
	return a.dashboard.Init()
}

func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			return a, tea.Quit
		case key.Matches(msg, keys.Tab):
			a.currentView = (a.currentView + 1) % 5
			return a, a.initCurrentView()
		case key.Matches(msg, keys.ShiftTab):
			a.currentView = (a.currentView + 4) % 5
			return a, a.initCurrentView()
		case key.Matches(msg, keys.One):
			a.currentView = viewDashboard
			return a, a.dashboard.Init()
		case key.Matches(msg, keys.Two):
			a.currentView = viewAgents
			return a, a.agents.Init()
		case key.Matches(msg, keys.Three):
			a.currentView = viewPolicies
			return a, a.policies.Init()
		case key.Matches(msg, keys.Four):
			a.currentView = viewRollouts
			return a, a.rollouts.Init()
		case key.Matches(msg, keys.Five):
			a.currentView = viewCerts
			return a, a.certs.Init()
		}

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
	}

	var cmd tea.Cmd
	switch a.currentView {
	case viewDashboard:
		cmd = a.dashboard.Update(msg)
	case viewAgents:
		cmd = a.agents.Update(msg)
	case viewPolicies:
		cmd = a.policies.Update(msg)
	case viewRollouts:
		cmd = a.rollouts.Update(msg)
	case viewCerts:
		cmd = a.certs.Update(msg)
	}
	return a, cmd
}

func (a *app) View() string {
	header := a.renderTabs()
	var body string

	switch a.currentView {
	case viewDashboard:
		body = a.dashboard.View()
	case viewAgents:
		body = a.agents.View()
	case viewPolicies:
		body = a.policies.View()
	case viewRollouts:
		body = a.rollouts.View()
	case viewCerts:
		body = a.certs.View()
	}

	footer := footerStyle.Render("tab/shift+tab: navigate | 1-5: jump | q: quit | r: refresh")

	return fmt.Sprintf("%s\n\n%s\n\n%s", header, body, footer)
}

func (a *app) initCurrentView() tea.Cmd {
	switch a.currentView {
	case viewDashboard:
		return a.dashboard.Init()
	case viewAgents:
		return a.agents.Init()
	case viewPolicies:
		return a.policies.Init()
	case viewRollouts:
		return a.rollouts.Init()
	case viewCerts:
		return a.certs.Init()
	}
	return nil
}

func (a *app) renderTabs() string {
	tabs := []string{"Dashboard", "Agents", "Policies", "Rollouts", "Certs"}
	var rendered []string

	for i, tab := range tabs {
		label := fmt.Sprintf(" %d:%s ", i+1, tab)
		if view(i) == a.currentView {
			rendered = append(rendered, activeTabStyle.Render(label))
		} else {
			rendered = append(rendered, inactiveTabStyle.Render(label))
		}
	}

	row := strings.Join(rendered, tabGapStyle.Render(" "))
	return titleStyle.Render("warmor") + "  " + row
}

// --- Styles ---

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205"))

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Padding(0, 1)

	tabGapStyle = lipgloss.NewStyle()

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))
)

// --- Keybindings ---

type keyMap struct {
	Quit     key.Binding
	Tab      key.Binding
	ShiftTab key.Binding
	Refresh  key.Binding
	One      key.Binding
	Two      key.Binding
	Three    key.Binding
	Four     key.Binding
	Five     key.Binding
}

var keys = keyMap{
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c")),
	Tab:      key.NewBinding(key.WithKeys("tab")),
	ShiftTab: key.NewBinding(key.WithKeys("shift+tab")),
	Refresh:  key.NewBinding(key.WithKeys("r")),
	One:      key.NewBinding(key.WithKeys("1")),
	Two:      key.NewBinding(key.WithKeys("2")),
	Three:    key.NewBinding(key.WithKeys("3")),
	Four:     key.NewBinding(key.WithKeys("4")),
	Five:     key.NewBinding(key.WithKeys("5")),
}
