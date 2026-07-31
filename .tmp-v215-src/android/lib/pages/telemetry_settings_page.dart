import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/telemetry_settings.dart';
import '../services/otlp_exporter.dart';
import '../services/telemetry_identity.dart';
import '../services/telemetry_settings_store.dart';
import '../widgets/app_section_card.dart';

class TelemetrySettingsPage extends StatefulWidget {
  const TelemetrySettingsPage({super.key});

  @override
  State<TelemetrySettingsPage> createState() => _TelemetrySettingsPageState();
}

class _TelemetrySettingsPageState extends State<TelemetrySettingsPage> {
  final _store = TelemetrySettingsStore();
  final _endpointController = TextEditingController();

  TelemetrySettings _settings = const TelemetrySettings();
  String _machineId = '';
  String _deviceLabel = '';
  bool _loading = true;
  bool _uploading = false;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    await TelemetryIdentity.installIfNeeded();
    final settings = await _store.settings();
    final id = await TelemetryIdentity.machineId();
    final attrs = await TelemetryIdentity.resourceAttributes();
    final model = attrs['device.model'] ?? 'unknown';
    final osName = attrs['os.name'] ?? 'Android';
    final osVersion = attrs['os.version'] ?? '';
    if (!mounted) return;
    setState(() {
      _settings = settings;
      _machineId = id;
      _deviceLabel = 'device: $model / $osName $osVersion';
      _loading = false;
      _endpointController.text = settings.customEndpoint;
    });
  }

  TelemetrySettings _applyForm() {
    return _settings.copyWith(
      customEndpoint: _endpointController.text.trim(),
    );
  }

  Future<void> _save() async {
    final next = _applyForm();
    if (next.uploadEnabled &&
        next.destination == TelemetryDestination.custom &&
        next.customEndpoint.trim().isEmpty) {
      _showMessage('请填写 OTLP HTTP Endpoint');
      return;
    }
    if (next.uploadEnabled && next.effectiveEndpoint.isNotEmpty) {
      final uri = Uri.tryParse(next.effectiveEndpoint);
      if (uri == null || uri.host.isEmpty) {
        _showMessage('OTLP HTTP Endpoint 无效');
        return;
      }
    }
    await _store.save(next);
    if (!mounted) return;
    setState(() => _settings = next);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('遥测设置已保存')),
    );
  }

  Future<void> _copyMachineId() async {
    await Clipboard.setData(ClipboardData(text: _machineId));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('machine.id 已复制')),
    );
  }

  Future<void> _uploadTestLog() async {
    final next = _applyForm();
    if (!next.canUpload || !next.includeCrashReports) return;

    setState(() => _uploading = true);
    try {
      await OtlpExporter.exportLogs(
        settings: next,
        records: [
          OtlpLogRecord(
            timeUnixNano: DateTime.now().microsecondsSinceEpoch * 1000,
            severityText: 'INFO',
            body: 'openppp2 android telemetry test upload',
            attributes: {
              'openppp2.component': const OtlpValue.string('flutter_app'),
              'openppp2.event': const OtlpValue.string('manual_test'),
            },
          ),
        ],
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('测试日志已上传')),
      );
    } on OtlpExportException catch (e) {
      _showMessage(e.message);
    } catch (e) {
      _showMessage(e.toString());
    } finally {
      if (mounted) setState(() => _uploading = false);
    }
  }

  void _showMessage(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  void dispose() {
    _endpointController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final next = _applyForm();
    final usesCustom = next.destination == TelemetryDestination.custom;
    final nativeEnabled = next.canUpload && next.includeNativeTelemetry;

    if (_loading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('遥测'),
        centerTitle: true,
        actions: [
          TextButton(
            onPressed: _save,
            child: const Text('保存'),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const AppSectionHeader('设备标识'),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '短 ID: ${_machineId.isEmpty ? '…' : _machineId.substring(0, _machineId.length < 12 ? _machineId.length : 12)}',
                    style: theme.textTheme.bodyMedium,
                  ),
                  const SizedBox(height: 8),
                  SelectableText(
                    'machine.id: $_machineId',
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontFamily: 'monospace',
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (_deviceLabel.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    Text(
                      _deviceLabel,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                  const SizedBox(height: 12),
                  TextButton.icon(
                    onPressed: _machineId.isEmpty ? null : _copyMachineId,
                    icon: const Icon(Icons.copy_rounded, size: 18),
                    label: const Text('复制 machine.id'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          const AppSectionHeader('上传'),
          Card(
            child: Column(
              children: [
                SwitchListTile(
                  secondary: const Icon(Icons.cloud_upload_outlined),
                  title: const Text('启用遥测上传'),
                  subtitle: const Text('OTLP/HTTP JSON'),
                  value: next.uploadEnabled,
                  onChanged: (v) => setState(
                    () => _settings = _settings.copyWith(uploadEnabled: v),
                  ),
                ),
                const Divider(height: 0),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                  child: SegmentedButton<TelemetryDestination>(
                    segments: TelemetryDestination.values
                        .map(
                          (d) => ButtonSegment(
                            value: d,
                            label: Text(d.label),
                          ),
                        )
                        .toList(),
                    selected: {next.destination},
                    onSelectionChanged: (s) => setState(
                      () => _settings = _settings.copyWith(
                        destination: s.first,
                      ),
                    ),
                  ),
                ),
                if (!usesCustom) ...[
                  const SizedBox(height: 8),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: Text(
                      TelemetrySettings.developerEndpoint,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
                if (usesCustom) ...[
                  const SizedBox(height: 8),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                    child: TextField(
                      controller: _endpointController,
                      decoration: const InputDecoration(
                        labelText: 'OTLP HTTP Endpoint',
                        hintText: 'https://collector.example.com',
                        border: OutlineInputBorder(),
                      ),
                      keyboardType: TextInputType.url,
                      onChanged: (_) => setState(() {}),
                    ),
                  ),
                ] else
                  const SizedBox(height: 12),
              ],
            ),
          ),
          const SizedBox(height: 12),
          const AppSectionHeader('数据'),
          Card(
            child: Column(
              children: [
                SwitchListTile(
                  title: const Text('应用日志 / 崩溃'),
                  subtitle: const Text('通过 Flutter 侧 OTLP 上传测试日志'),
                  value: next.includeCrashReports,
                  onChanged: (v) => setState(
                    () => _settings = _settings.copyWith(
                      includeCrashReports: v,
                    ),
                  ),
                ),
                const Divider(height: 0),
                SwitchListTile(
                  title: const Text('Native Telemetry'),
                  subtitle: const Text('VPN 进程内 C++ 引擎遥测'),
                  value: next.includeNativeTelemetry,
                  onChanged: (v) => setState(
                    () => _settings = _settings.copyWith(
                      includeNativeTelemetry: v,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          const AppSectionHeader('Native'),
          Card(
            child: Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                  child: SegmentedButton<int>(
                    segments: const [
                      ButtonSegment(value: 0, label: Text('Info')),
                      ButtonSegment(value: 1, label: Text('Verb')),
                      ButtonSegment(value: 2, label: Text('Debug')),
                      ButtonSegment(value: 3, label: Text('Trace')),
                    ],
                    selected: {next.nativeLogLevel.clamp(0, 3)},
                    onSelectionChanged: nativeEnabled
                        ? (s) => setState(
                              () => _settings = _settings.copyWith(
                                nativeLogLevel: s.first,
                              ),
                            )
                        : null,
                  ),
                ),
                SwitchListTile(
                  title: const Text('Metrics'),
                  subtitle: const Text('Counter / Gauge / Histogram'),
                  value: next.nativeMetricsEnabled,
                  onChanged: null,
                ),
                const Divider(height: 0),
                SwitchListTile(
                  title: const Text('Spans'),
                  subtitle: const Text('Trace spans'),
                  value: next.nativeSpansEnabled,
                  onChanged: nativeEnabled
                      ? (v) => setState(
                            () => _settings = _settings.copyWith(
                              nativeSpansEnabled: v,
                            ),
                          )
                      : null,
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: Text(
                    'Native 遥测在 VPN 服务启动时安装 HTTP 传输；连接时写入配置 telemetry 块。',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          FilledButton(
            onPressed: next.canUpload && next.includeCrashReports && !_uploading
                ? _uploadTestLog
                : null,
            child: Text(_uploading ? '上传中…' : '上传测试日志'),
          ),
        ],
      ),
    );
  }
}
