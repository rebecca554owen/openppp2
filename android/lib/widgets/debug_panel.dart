import 'package:flutter/material.dart';

class DebugPanel extends StatelessWidget {
  final String stateText;
  final String logPath;
  final String logText;
  final VoidCallback onRefresh;
  final VoidCallback onCopy;
  final VoidCallback onClear;
  final VoidCallback onStop;

  const DebugPanel({
    super.key,
    required this.stateText,
    required this.logPath,
    required this.logText,
    required this.onRefresh,
    required this.onCopy,
    required this.onClear,
    required this.onStop,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    '调试面板',
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                IconButton(
                  tooltip: '刷新日志',
                  onPressed: onRefresh,
                  icon: const Icon(Icons.refresh),
                ),
                IconButton(
                  tooltip: '复制日志',
                  onPressed: onCopy,
                  icon: const Icon(Icons.copy),
                ),
                IconButton(
                  tooltip: '清空日志',
                  onPressed: onClear,
                  icon: const Icon(Icons.delete_outline),
                ),
                IconButton(
                  tooltip: '停止 VPN',
                  onPressed: onStop,
                  icon: const Icon(Icons.stop_circle_outlined),
                ),
              ],
            ),
            Text('状态: $stateText'),
            const SizedBox(height: 4),
            SelectableText(
              '日志: ${logPath.isEmpty ? '(未知)' : logPath}',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Container(
              constraints: const BoxConstraints(minHeight: 160, maxHeight: 260),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  logText.trim().isEmpty ? '(暂无日志)' : logText,
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
