package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	content := ""
	switch m.currentTab {
	case 0:
		content = m.renderDashboard()
	case 1:
		content = m.renderInstances()
	case 2:
		content = m.renderLogs()
	case 3:
		content = m.renderConfigs()
	case 4:
		content = m.renderBinaries()
	}

	header := m.renderHeader()
	statusBar := m.renderStatusBar()
	help := m.renderHelp()
	bodyHeight := max(8, m.height-lipgloss.Height(header)-lipgloss.Height(statusBar)-lipgloss.Height(help)-2)
	body := lipgloss.NewStyle().Height(bodyHeight).Render(content)
	return lipgloss.NewStyle().Background(bgColor).Foreground(textColor).Render(lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar, help))
}

func (m model) renderHeader() string {
	var tabs []string
	for i, tab := range m.tabs {
		style := mutedStyle.Padding(0, 1)
		if i == m.currentTab {
			style = accentStyle.Padding(0, 1)
		}
		tabs = append(tabs, style.Render("["+tab+"]"))
	}
	left := titleStyle.Render("OpenPPP2 Guardian TUI")
	right := lipgloss.NewStyle().Foreground(textColor).Background(surfaceColor).Padding(0, 1).Render(strings.Join(tabs, " "))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m model) renderDashboard() string {
	statusLines := []string{"Guardian status"}
	if m.status == nil {
		statusLines = append(statusLines, mutedStyle.Render("Disconnected"))
	} else {
		statusLines = append(statusLines,
			fmt.Sprintf("Version: %s", m.status.Version),
			fmt.Sprintf("Uptime: %s", m.status.Uptime),
			fmt.Sprintf("Instances: %d", m.status.InstanceCount),
			fmt.Sprintf("Binaries: %d", len(m.binaries)),
		)
	}

	instanceLines := []string{"Instances"}
	if len(m.instances) == 0 {
		instanceLines = append(instanceLines, mutedStyle.Render("No instances configured. Go to Instances tab to create one."))
	} else {
		instanceLines = append(instanceLines, "name            status      pid      uptime      restart")
		for _, inst := range m.instances {
			state := successStyle.Render("● running")
			pid := fmt.Sprintf("%d", inst.PID)
			uptime := "-"
			if inst.StartedAt != nil {
				uptime = relativeTime(*inst.StartedAt)
			}
			if !inst.Running {
				state = errorStyle.Render("● stopped")
				pid = "-"
				uptime = "-"
			}
			instanceLines = append(instanceLines, fmt.Sprintf("%-15s %-18s %-8s %-10s %t", inst.Name, state, pid, uptime, inst.AutoRestart))
		}
	}

	left := panelStyle.Width(max(30, m.width/3)).Render(strings.Join(statusLines, "\n"))
	right := panelStyle.Width(max(45, m.width-40)).Render(strings.Join(instanceLines, "\n"))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m model) renderInstances() string {
	leftW := max(30, m.width/3)
	rightW := max(40, m.width-leftW-4)
	left := panelStyle.Width(leftW).Render(m.instancesTable.View())

	detail := []string{"Instance detail"}
	if inst := m.selectedInstanceData(); inst != nil {
		state := "stopped"
		if inst.Running {
			state = "running"
		}
		detail = append(detail,
			fmt.Sprintf("Name: %s", inst.Name),
			fmt.Sprintf("Status: %s", state),
			fmt.Sprintf("PID: %d", inst.PID),
			fmt.Sprintf("Binary: %s", inst.Binary),
			fmt.Sprintf("Config: %s", inst.ConfigPath),
			fmt.Sprintf("WorkDir: %s", inst.WorkDir),
			fmt.Sprintf("Args: %s", strings.Join(inst.Args, " ")),
			fmt.Sprintf("Started: %s", formatTimePtr(inst.StartedAt)),
			fmt.Sprintf("Stopped: %s", formatTimePtr(inst.StoppedAt)),
			fmt.Sprintf("AutoRestart: %t (%d)", inst.AutoRestart, inst.RestartCount),
		)
		if inst.LastExit != nil {
			detail = append(detail, fmt.Sprintf("Last exit: code=%d success=%t at=%s", inst.LastExit.Code, inst.LastExit.Success, relativeTime(inst.LastExit.At)))
			if inst.LastExit.Error != "" {
				detail = append(detail, fmt.Sprintf("Last error: %s", inst.LastExit.Error))
			}
		}
		detail = append(detail, "", "Actions: [Start] [Stop] [Restart] [Delete]")
	} else {
		detail = append(detail, mutedStyle.Render("Select an instance to view details."))
	}

	right := panelStyle.Width(rightW).Render(strings.Join(detail, "\n"))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	footer := mutedStyle.Render("n: new instance | d: delete | s: start | S: stop | R: restart")
	if m.confirmDelete {
		footer = errorStyle.Render("Press Enter to confirm delete, Esc to cancel")
	}
	if m.newInstance {
		return lipgloss.JoinVertical(lipgloss.Left, body, footer, m.renderNewInstanceModal())
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, footer)
}

func (m model) renderLogs() string {
	selector := fmt.Sprintf("Instance: %s", fallback(m.selectedInstance, "-"))
	filter := fmt.Sprintf("Filter: [%s]", m.logStream)
	if m.logPaused {
		filter += " paused"
	}
	if m.logSearch != "" {
		filter += " search=" + m.logSearch
	}
	top := panelStyle.Width(max(30, m.width-2)).Render(selector + "   " + filter)
	logs := panelStyle.Width(max(30, m.width-2)).Height(max(8, m.height-12)).Render(m.logViewport.View())
	if m.searching {
		return lipgloss.JoinVertical(lipgloss.Left, top, logs, panelStyle.Render(m.searchInput.View()))
	}
	return lipgloss.JoinVertical(lipgloss.Left, top, logs)
}

func (m model) renderConfigs() string {
	leftW := max(30, m.width/3)
	rightW := max(40, m.width-leftW-4)
	left := panelStyle.Width(leftW).Render(m.profilesTable.View())
	content := basicJSONColorize(m.profileContent)
	if m.editingProfile {
		content = m.profileEditor.View()
	}
	right := panelStyle.Width(rightW).Render(content)
	footer := mutedStyle.Render("e: edit | ctrl+s: save | d: delete")
	if m.confirmDelete {
		footer = errorStyle.Render("Press Enter to confirm profile delete, Esc to cancel")
	}
	return lipgloss.JoinVertical(lipgloss.Left, lipgloss.JoinHorizontal(lipgloss.Top, left, right), footer)
}

func (m model) renderBinaries() string {
	body := panelStyle.Width(max(30, m.width-2)).Render(m.binariesTable.View())
	footer := mutedStyle.Render("d: discover | Del: delete | Enter: register selected discovered binary")
	if m.showDiscover {
		footer = m.renderDiscoverDialog()
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, footer)
}

func (m model) renderHelp() string {
	return helpStyle.Render("Tab: next | Shift+Tab: prev | 1-5: switch | ↑↓: navigate | Enter: select | s/S/R: start/stop/restart | r: refresh | q: quit")
}

func (m model) renderStatusBar() string {
	state := successStyle.Render("connected")
	if !m.connected {
		state = errorStyle.Render("disconnected")
	}
	refreshed := "never"
	if !m.lastRefresh.IsZero() {
		refreshed = relativeTime(m.lastRefresh)
	}
	text := fmt.Sprintf("State: %s | Last refresh: %s | %s", state, refreshed, m.statusNote)
	if m.err != nil {
		text += " | err: " + m.err.Error()
	}
	return panelStyle.Width(max(30, m.width-2)).Render(text)
}

func (m model) renderNewInstanceModal() string {
	lines := []string{accentStyle.Render("New Instance")}
	labels := []string{"Name", "Binary", "Config", "Args"}
	for i, input := range m.newInstanceForm {
		lines = append(lines, fmt.Sprintf("%s: %s", labels[i], input.View()))
	}
	lines = append(lines, mutedStyle.Render("Enter: next/submit | Esc: cancel | Up/Down: field"))
	return panelStyle.Width(70).Render(strings.Join(lines, "\n"))
}

func (m model) renderDiscoverDialog() string {
	lines := []string{accentStyle.Render("Discover binaries"), fmt.Sprintf("Directory: %s", m.discoverDir), m.discoverTable.View(), mutedStyle.Render("r: rediscover | Enter: register | Esc: close")}
	return panelStyle.Width(max(40, m.width-6)).Render(strings.Join(lines, "\n"))
}

func basicJSONColorize(s string) string {
	if strings.TrimSpace(s) == "" {
		return mutedStyle.Render("No profile selected.")
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, ":"); idx > 0 && strings.HasPrefix(trimmed, "\"") {
			key := trimmed[:idx]
			value := strings.TrimSpace(trimmed[idx+1:])
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			out = append(out, indent+accentStyle.Render(key)+": "+successStyle.Render(value))
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return relativeTime(*t)
}

func fallback(v string, alt string) string {
	if v == "" {
		return alt
	}
	return v
}
