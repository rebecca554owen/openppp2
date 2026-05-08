package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type dashboardDataMsg struct {
	status    *StatusResponse
	instances []InstanceResponse
	profiles  []ProfileInfo
	binaries  []BinaryInfo
	err       error
	at        time.Time
}

type instanceDetailMsg struct {
	instance *InstanceResponse
	err      error
}

type logsLoadedMsg struct {
	name string
	logs []LogEntry
	err  error
}

type profileLoadedMsg struct {
	profile *Profile
	err     error
}

type discoveredMsg struct {
	items []DiscoveredBinary
	err   error
}

type actionDoneMsg struct {
	err error
	note string
}

type tickMsg time.Time
type eventMsg Event
type logMsg LogEntry

type model struct {
	client        *Client
	width, height int
	currentTab    int
	tabs          []string

	status    *StatusResponse
	instances []InstanceResponse

	selectedInstance   string
	showInstanceDetail bool

	logLines   []LogEntry
	logStream  string
	logPaused  bool
	logSearch  string
	searching  bool
	searchInput textinput.Model

	profiles        []ProfileInfo
	selectedProfile string
	profileContent  string
	editingProfile  bool
	editBuffer      string

	binaries     []BinaryInfo
	discoverDir  string
	discovered   []DiscoveredBinary
	showDiscover bool

	err          error
	loading      bool
	lastRefresh  time.Time
	connected    bool
	statusNote   string
	confirmDelete bool

	instancesTable table.Model
	profilesTable  table.Model
	binariesTable  table.Model
	discoverTable  table.Model
	logViewport    viewport.Model
	profileEditor  textarea.Model

	newInstance     bool
	newInstanceForm []textinput.Model
	newInstanceIdx  int

	eventsCancel context.CancelFunc
	logsCancel   context.CancelFunc
	eventsCh     <-chan Event
	logsCh       <-chan LogEntry
}

var (
	bgColor      = lipgloss.Color("#0d1117")
	surfaceColor = lipgloss.Color("#161b22")
	accentColor  = lipgloss.Color("#58a6ff")
	successColor = lipgloss.Color("#3fb950")
	dangerColor  = lipgloss.Color("#f85149")
	warningColor = lipgloss.Color("#d29922")
	textColor    = lipgloss.Color("#c9d1d9")
	dimColor     = lipgloss.Color("#8b949e")

	titleStyle = lipgloss.NewStyle().Foreground(textColor).Background(surfaceColor).Bold(true).Padding(0, 1)
	panelStyle = lipgloss.NewStyle().Background(surfaceColor).Foreground(textColor).Border(lipgloss.RoundedBorder()).BorderForeground(dimColor).Padding(1)
	helpStyle  = lipgloss.NewStyle().Foreground(dimColor).Background(surfaceColor).Padding(0, 1)
	mutedStyle = lipgloss.NewStyle().Foreground(dimColor)
	accentStyle = lipgloss.NewStyle().Foreground(accentColor).Bold(true)
	errorStyle = lipgloss.NewStyle().Foreground(dangerColor).Bold(true)
	successStyle = lipgloss.NewStyle().Foreground(successColor).Bold(true)
)

func newModel(client *Client) model {
	instancesTable := table.New(
		table.WithColumns([]table.Column{{Title: "Name", Width: 18}, {Title: "State", Width: 10}, {Title: "PID", Width: 8}}),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		)
	profilesTable := table.New(
		table.WithColumns([]table.Column{{Title: "Profile", Width: 24}, {Title: "Updated", Width: 14}}),
		table.WithRows([]table.Row{}),
	)
	binariesTable := table.New(
		table.WithColumns([]table.Column{{Title: "ID", Width: 10}, {Title: "Path", Width: 42}, {Title: "Arch", Width: 8}, {Title: "Size", Width: 10}, {Title: "Active", Width: 8}}),
		table.WithRows([]table.Row{}),
	)
	discoverTable := table.New(
		table.WithColumns([]table.Column{{Title: "Name", Width: 16}, {Title: "Path", Width: 42}, {Title: "Arch", Width: 8}, {Title: "Size", Width: 10}}),
		table.WithRows([]table.Row{}),
	)
	for _, tbl := range []*table.Model{&instancesTable, &profilesTable, &binariesTable, &discoverTable} {
		s := table.DefaultStyles()
		s.Header = s.Header.Foreground(accentColor).BorderForeground(dimColor).Bold(true)
		s.Selected = s.Selected.Foreground(textColor).Background(accentColor).Bold(true)
		tbl.SetStyles(s)
	}

	vp := viewport.New(0, 0)
	vp.Style = lipgloss.NewStyle().Background(surfaceColor).Foreground(textColor)

	searchInput := textinput.New()
	searchInput.Placeholder = "search logs"
	searchInput.Prompt = "/ "

	editor := textarea.New()
	editor.Placeholder = "profile content"
	editor.ShowLineNumbers = true
	editor.SetHeight(20)
	editor.FocusedStyle.Base = editor.FocusedStyle.Base.Foreground(textColor).Background(surfaceColor)

	form := make([]textinput.Model, 4)
	placeholders := []string{"name", "binary path", "config path", "args (space separated)"}
	for i := range form {
		form[i] = textinput.New()
		form[i].Placeholder = placeholders[i]
		form[i].Width = 48
	}
	form[0].Focus()

	return model{
		client:           client,
		tabs:             []string{"Dashboard", "Instances", "Logs", "Configs", "Binaries"},
		logStream:        "all",
		discoverDir:      ".",
		searchInput:      searchInput,
		profileEditor:    editor,
		instancesTable:   instancesTable,
		profilesTable:    profilesTable,
		binariesTable:    binariesTable,
		discoverTable:    discoverTable,
		logViewport:      vp,
		newInstanceForm:  form,
		statusNote:       "Connecting...",
	}
}

func (m model) Init() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.eventsCancel = cancel
	ch, err := m.client.SubscribeEvents(ctx)
	if err == nil {
		m.eventsCh = ch
	}
	return tea.Batch(refreshAllCmd(m.client), tickCmd(), waitEventCmd(ch))
}

func refreshAllCmd(client *Client) tea.Cmd {
	return func() tea.Msg {
		status, err := client.Status()
		if err != nil {
			return dashboardDataMsg{err: err, at: time.Now()}
		}
		instances, err := client.ListInstances()
		if err != nil {
			return dashboardDataMsg{err: err, at: time.Now()}
		}
		profiles, _ := client.ListProfiles()
		binaries, _ := client.ListBinaries()
		return dashboardDataMsg{status: status, instances: instances, profiles: profiles, binaries: binaries, at: time.Now()}
	}
}

func loadInstanceCmd(client *Client, name string) tea.Cmd {
	return func() tea.Msg {
		inst, err := client.GetInstance(name)
		return instanceDetailMsg{instance: inst, err: err}
	}
}

func loadLogsCmd(client *Client, name string) tea.Cmd {
	return func() tea.Msg {
		logs, err := client.GetLogs(name, 200)
		return logsLoadedMsg{name: name, logs: logs, err: err}
	}
}

func loadProfileCmd(client *Client, name string) tea.Cmd {
	return func() tea.Msg {
		profile, err := client.GetProfile(name)
		return profileLoadedMsg{profile: profile, err: err}
	}
}

func discoverCmd(client *Client, dir string) tea.Cmd {
	return func() tea.Msg {
		items, err := client.DiscoverBinaries(dir)
		return discoveredMsg{items: items, err: err}
	}
}

func actionCmd(fn func() error, note string) tea.Cmd {
	return func() tea.Msg {
		return actionDoneMsg{err: fn(), note: note}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func waitEventCmd(ch <-chan Event) tea.Cmd {
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		evt, ok := <-ch
		if !ok {
			return actionDoneMsg{err: fmt.Errorf("event stream disconnected")}
		}
		return eventMsg(evt)
	}
}

func waitLogCmd(ch <-chan LogEntry) tea.Cmd {
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		entry, ok := <-ch
		if !ok {
			return actionDoneMsg{err: fmt.Errorf("log stream disconnected")}
		}
		return logMsg(entry)
	}
}

func (m *model) syncSelections() {
	if m.selectedInstance == "" && len(m.instances) > 0 {
		m.selectedInstance = m.instances[0].Name
	}
	if m.selectedProfile == "" && len(m.profiles) > 0 {
		m.selectedProfile = m.profiles[0].Name
	}
	m.instancesTable.SetRows(instanceRows(m.instances))
	m.profilesTable.SetRows(profileRows(m.profiles))
	m.binariesTable.SetRows(binaryRows(m.binaries))
	m.discoverTable.SetRows(discoveredRows(m.discovered))
	for i, inst := range m.instances {
		if inst.Name == m.selectedInstance {
			m.instancesTable.SetCursor(i)
			break
		}
	}
	for i, p := range m.profiles {
		if p.Name == m.selectedProfile {
			m.profilesTable.SetCursor(i)
			break
		}
	}
}

func instanceRows(items []InstanceResponse) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, item := range items {
		state := "stopped"
		pid := "-"
		if item.Running {
			state = "running"
			pid = fmt.Sprintf("%d", item.PID)
		}
		rows = append(rows, table.Row{item.Name, state, pid})
	}
	return rows
}

func profileRows(items []ProfileInfo) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, item := range items {
		rows = append(rows, table.Row{item.Name, relativeTime(item.UpdatedAt)})
	}
	return rows
}

func binaryRows(items []BinaryInfo) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, item := range items {
		active := ""
		if item.Active {
			active = "*"
		}
		id := item.ID
		if len(id) > 8 {
			id = id[:8]
		}
		rows = append(rows, table.Row{id, item.Path, item.Arch, humanSize(item.Size), active})
	}
	return rows
}

func discoveredRows(items []DiscoveredBinary) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, item := range items {
		rows = append(rows, table.Row{item.Name, item.Path, item.Arch, humanSize(item.Size)})
	}
	return rows
}

func (m *model) selectedInstanceData() *InstanceResponse {
	for i := range m.instances {
		if m.instances[i].Name == m.selectedInstance {
			return &m.instances[i]
		}
	}
	return nil
}

func (m *model) startLogSubscription() tea.Cmd {
	if m.logsCancel != nil {
		m.logsCancel()
		m.logsCancel = nil
	}
	if m.selectedInstance == "" {
		m.logsCh = nil
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.logsCancel = cancel
	ch, err := m.client.SubscribeLogs(ctx, m.selectedInstance)
	if err != nil {
		m.err = err
		return nil
	}
	m.logsCh = ch
	return waitLogCmd(ch)
}

func (m *model) updateLogViewport() {
	lines := make([]string, 0, len(m.logLines))
	query := strings.ToLower(strings.TrimSpace(m.logSearch))
	for _, entry := range m.logLines {
		if m.logStream != "all" && entry.Stream != m.logStream {
			continue
		}
		line := fmt.Sprintf("%s [%s] %s", entry.At.Format("15:04:05"), entry.Stream, strings.TrimRight(entry.Text, "\n"))
		if query != "" && !strings.Contains(strings.ToLower(line), query) {
			continue
		}
		lines = append(lines, line)
	}
	m.logViewport.SetContent(strings.Join(lines, "\n"))
	if !m.logPaused {
		m.logViewport.GotoBottom()
	}
	if m.height > 0 {
		m.logViewport.Height = max(8, m.height-11)
	}
	if m.width > 0 {
		m.logViewport.Width = max(20, m.width-6)
	}
}

func relativeTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func humanSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	f := float64(size)
	idx := 0
	for f >= 1024 && idx < len(units)-1 {
		f /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d%s", size, units[idx])
	}
	return fmt.Sprintf("%.1f%s", f, units[idx])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
