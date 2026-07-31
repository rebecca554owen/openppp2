package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.logViewport.Width = max(20, m.width-6)
		m.logViewport.Height = max(8, m.height-11)
	case tickMsg:
		cmds = append(cmds, refreshAllCmd(m.client), tickCmd())
	case dashboardDataMsg:
		m.lastRefresh = msg.at
		if msg.err != nil {
			m.err = msg.err
			m.connected = false
			m.statusNote = "Disconnected"
			break
		}
		m.connected = true
		m.status = msg.status
		m.instances = msg.instances
		m.profiles = msg.profiles
		m.binaries = msg.binaries
		m.statusNote = "Connected"
		m.err = nil
		m.syncSelections()
		m.updateLogViewport()
		if m.currentTab == 1 && m.selectedInstance != "" {
			cmds = append(cmds, loadInstanceCmd(m.client, m.selectedInstance))
		}
		if m.currentTab == 2 && m.selectedInstance != "" && len(m.logLines) == 0 {
			cmds = append(cmds, loadLogsCmd(m.client, m.selectedInstance), m.startLogSubscription())
		}
		if m.currentTab == 3 && m.selectedProfile != "" && m.profileContent == "" {
			cmds = append(cmds, loadProfileCmd(m.client, m.selectedProfile))
		}
	case instanceDetailMsg:
		m.showInstanceDetail = msg.instance != nil
		m.err = msg.err
		if msg.instance != nil {
			m.selectedInstance = msg.instance.Name
		}
	case logsLoadedMsg:
		m.err = msg.err
		if msg.err == nil && msg.name == m.selectedInstance {
			m.logLines = msg.logs
			m.updateLogViewport()
		}
	case profileLoadedMsg:
		m.err = msg.err
		if msg.profile != nil {
			m.selectedProfile = msg.profile.Name
			m.profileContent = msg.profile.Content
			m.editBuffer = msg.profile.Content
			m.profileEditor.SetValue(msg.profile.Content)
		}
	case discoveredMsg:
		m.err = msg.err
		if msg.err == nil {
			m.discovered = msg.items
			m.discoverTable.SetRows(discoveredRows(msg.items))
		}
	case actionDoneMsg:
		m.err = msg.err
		if msg.err == nil && msg.note != "" {
			m.statusNote = msg.note
			cmds = append(cmds, refreshAllCmd(m.client))
			if m.currentTab == 2 && m.selectedInstance != "" {
				cmds = append(cmds, loadLogsCmd(m.client, m.selectedInstance))
			}
		}
	case eventMsg:
		m.statusNote = fmt.Sprintf("Event: %s %s", msg.Type, msg.Name)
		cmds = append(cmds, refreshAllCmd(m.client), waitEventCmd(m.eventsCh))
	case logMsg:
		m.logLines = append(m.logLines, LogEntry(msg))
		if len(m.logLines) > 2000 {
			m.logLines = m.logLines[len(m.logLines)-2000:]
		}
		m.updateLogViewport()
		cmds = append(cmds, waitLogCmd(m.logsCh))
	case tea.KeyMsg:
		if m.editingProfile {
			return m.updateProfileEditor(msg)
		}
		if m.newInstance {
			return m.updateNewInstanceForm(msg)
		}
		if m.showDiscover {
			return m.updateDiscover(msg)
		}
		if m.searching {
			return m.updateLogSearch(msg)
		}

		switch msg.String() {
		case "ctrl+c", "q":
			if m.eventsCancel != nil {
				m.eventsCancel()
			}
			if m.logsCancel != nil {
				m.logsCancel()
			}
			return m, tea.Quit
		case "tab":
			m.currentTab = (m.currentTab + 1) % len(m.tabs)
		case "shift+tab":
			m.currentTab = (m.currentTab - 1 + len(m.tabs)) % len(m.tabs)
		case "1", "2", "3", "4", "5":
			m.currentTab = int(msg.String()[0] - '1')
		case "r":
			cmds = append(cmds, refreshAllCmd(m.client))
		case "enter":
			cmds = append(cmds, m.handleEnter())
		case "esc":
			m.confirmDelete = false
			m.showInstanceDetail = false
		case "s":
			cmds = append(cmds, m.instanceAction(func(name string) error { _, err := m.client.StartInstance(name); return err }, "Instance started"))
		case "S":
			cmds = append(cmds, m.instanceAction(func(name string) error { _, err := m.client.StopInstance(name); return err }, "Instance stopped"))
		case "R":
			cmds = append(cmds, m.instanceAction(func(name string) error { _, err := m.client.RestartInstance(name); return err }, "Instance restarted"))
		case "d":
			if m.currentTab == 4 {
				m.showDiscover = true
				cmds = append(cmds, discoverCmd(m.client, m.discoverDir))
			} else {
				m.confirmDelete = !m.confirmDelete
			}
		case "delete":
			if m.currentTab == 4 {
				cmds = append(cmds, m.deleteSelected())
			}
		case "n":
			if m.currentTab == 1 {
				m.newInstance = true
				m.newInstanceIdx = 0
				for i := range m.newInstanceForm {
					m.newInstanceForm[i].SetValue("")
					m.newInstanceForm[i].Blur()
				}
				m.newInstanceForm[0].Focus()
			}
		case "e":
			if m.currentTab == 3 && m.selectedProfile != "" {
				m.editingProfile = true
				m.profileEditor.SetValue(m.profileContent)
				m.profileEditor.Focus()
			}
		case " ":
			if m.currentTab == 2 {
				m.logPaused = !m.logPaused
				m.updateLogViewport()
			}
		case "/":
			if m.currentTab == 2 {
				m.searching = true
				m.searchInput.SetValue(m.logSearch)
				m.searchInput.Focus()
			}
		case "left":
			if m.currentTab == 2 {
				cmds = append(cmds, m.cycleLogInstance(-1))
			}
		case "right":
			if m.currentTab == 2 {
				cmds = append(cmds, m.cycleLogInstance(1))
			}
		case "up", "down":
			cmds = append(cmds, m.handleNavigation(msg))
		}
	}

	return m, tea.Batch(cmds...)
}

func (m model) handleEnter() tea.Cmd {
	switch m.currentTab {
	case 1:
		row := m.instancesTable.Cursor()
		if row >= 0 && row < len(m.instances) {
			m.selectedInstance = m.instances[row].Name
			m.showInstanceDetail = true
			return loadInstanceCmd(m.client, m.selectedInstance)
		}
	case 2:
		return m.startLogSubscription()
	case 3:
		row := m.profilesTable.Cursor()
		if row >= 0 && row < len(m.profiles) {
			m.selectedProfile = m.profiles[row].Name
			return loadProfileCmd(m.client, m.selectedProfile)
		}
	case 4:
		if m.showDiscover {
			row := m.discoverTable.Cursor()
			if row >= 0 && row < len(m.discovered) {
				path := m.discovered[row].Path
				return actionCmd(func() error {
					_, err := m.client.RegisterBinary(path)
					return err
				}, "Binary registered")
			}
		}
	}
	if m.confirmDelete {
		return m.deleteSelected()
	}
	return nil
}

func (m model) handleNavigation(key tea.KeyMsg) tea.Cmd {
	switch m.currentTab {
	case 1:
		var cmd tea.Cmd
		m.instancesTable, cmd = m.instancesTable.Update(key)
		row := m.instancesTable.Cursor()
		if row >= 0 && row < len(m.instances) {
			m.selectedInstance = m.instances[row].Name
		}
		return cmd
	case 2:
		var cmd tea.Cmd
		m.logViewport, cmd = m.logViewport.Update(key)
		return cmd
	case 3:
		var cmd tea.Cmd
		m.profilesTable, cmd = m.profilesTable.Update(key)
		row := m.profilesTable.Cursor()
		if row >= 0 && row < len(m.profiles) {
			m.selectedProfile = m.profiles[row].Name
		}
		return cmd
	case 4:
		var cmd tea.Cmd
		m.binariesTable, cmd = m.binariesTable.Update(key)
		return cmd
	}
	return nil
}

func (m model) instanceAction(fn func(string) error, note string) tea.Cmd {
	if m.selectedInstance == "" {
		return nil
	}
	name := m.selectedInstance
	return actionCmd(func() error { return fn(name) }, note)
}

func (m model) deleteSelected() tea.Cmd {
	switch m.currentTab {
	case 1:
		if m.selectedInstance == "" {
			return nil
		}
		name := m.selectedInstance
		return actionCmd(func() error { return m.client.RemoveInstance(name) }, "Instance removed")
	case 3:
		if m.selectedProfile == "" {
			return nil
		}
		name := m.selectedProfile
		return actionCmd(func() error { return m.client.DeleteProfile(name) }, "Profile deleted")
	case 4:
		row := m.binariesTable.Cursor()
		if row < 0 || row >= len(m.binaries) {
			return nil
		}
		id := m.binaries[row].ID
		return actionCmd(func() error { return m.client.RemoveBinary(id) }, "Binary removed")
	}
	return nil
}

func (m model) cycleLogInstance(step int) tea.Cmd {
	if len(m.instances) == 0 {
		return nil
	}
	idx := 0
	for i, inst := range m.instances {
		if inst.Name == m.selectedInstance {
			idx = i
			break
		}
	}
	idx = (idx + step + len(m.instances)) % len(m.instances)
	m.selectedInstance = m.instances[idx].Name
	m.logLines = nil
	return tea.Batch(loadLogsCmd(m.client, m.selectedInstance), m.startLogSubscription())
}

func (m model) updateLogSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searching = false
		m.searchInput.Blur()
		return m, nil
	case "enter":
		m.logSearch = strings.TrimSpace(m.searchInput.Value())
		m.searching = false
		m.searchInput.Blur()
		m.updateLogViewport()
		return m, nil
	}
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	return m, cmd
}

func (m model) updateDiscover(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.showDiscover = false
		return m, nil
	case "r":
		return m, discoverCmd(m.client, m.discoverDir)
	}
	var cmd tea.Cmd
	m.discoverTable, cmd = m.discoverTable.Update(msg)
	return m, cmd
}

func (m model) updateProfileEditor(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editingProfile = false
		m.profileEditor.Blur()
		m.profileEditor.SetValue(m.profileContent)
		return m, nil
	case "ctrl+s":
		content := m.profileEditor.Value()
		name := m.selectedProfile
		m.editingProfile = false
		m.profileEditor.Blur()
		return m, actionCmd(func() error { return m.client.SaveProfile(name, content) }, "Profile saved")
	}
	var cmd tea.Cmd
	m.profileEditor, cmd = m.profileEditor.Update(msg)
	return m, cmd
}

func (m model) updateNewInstanceForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.newInstance = false
		return m, nil
	case "enter":
		if m.newInstanceIdx < len(m.newInstanceForm)-1 {
			m.newInstanceForm[m.newInstanceIdx].Blur()
			m.newInstanceIdx++
			m.newInstanceForm[m.newInstanceIdx].Focus()
			return m, nil
		}
		name := strings.TrimSpace(m.newInstanceForm[0].Value())
		binary := strings.TrimSpace(m.newInstanceForm[1].Value())
		config := strings.TrimSpace(m.newInstanceForm[2].Value())
		args := strings.Fields(strings.TrimSpace(m.newInstanceForm[3].Value()))
		m.newInstance = false
		return m, actionCmd(func() error {
			_, err := m.client.CreateInstance(InstanceCreateRequest{Name: name, Binary: binary, ConfigPath: config, Args: args})
			return err
		}, "Instance created")
	case "up":
		if m.newInstanceIdx > 0 {
			m.newInstanceForm[m.newInstanceIdx].Blur()
			m.newInstanceIdx--
			m.newInstanceForm[m.newInstanceIdx].Focus()
		}
		return m, nil
	case "down":
		if m.newInstanceIdx < len(m.newInstanceForm)-1 {
			m.newInstanceForm[m.newInstanceIdx].Blur()
			m.newInstanceIdx++
			m.newInstanceForm[m.newInstanceIdx].Focus()
		}
		return m, nil
	}
	var cmds []tea.Cmd
	for i := range m.newInstanceForm {
		var cmd tea.Cmd
		m.newInstanceForm[i], cmd = m.newInstanceForm[i].Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}
