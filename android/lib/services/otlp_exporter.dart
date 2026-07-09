import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/telemetry_settings.dart';
import 'telemetry_identity.dart';

class OtlpExporter {
  OtlpExporter._();

  static Future<void> exportLogs({
    required TelemetrySettings settings,
    required List<OtlpLogRecord> records,
  }) async {
    if (!settings.canUpload) {
      throw const OtlpExportException('遥测上传未开启');
    }
    if (records.isEmpty) return;

    final url = TelemetrySettings.logsUrl(settings.effectiveEndpoint);
    if (url == null) {
      throw const OtlpExportException('OpenTelemetry endpoint 无效');
    }

    final attrs = await TelemetryIdentity.resourceAttributes();
    final payload = {
      'resourceLogs': [
        {
          'resource': {
            'attributes': attrs.entries
                .map((e) => _attributeJson(e.key, OtlpValue.string(e.value)))
                .toList(),
          },
          'scopeLogs': [
            {
              'scope': {
                'name': 'openppp2.android.app',
                'version': '1.0.0',
              },
              'logRecords': records.map(_logRecordJson).toList(),
            },
          ],
        },
      ],
    };

    final response = await http
        .post(
          Uri.parse(url),
          headers: const {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: jsonEncode(payload),
        )
        .timeout(const Duration(seconds: 12));

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final body = response.body;
      throw OtlpExportException(
        body.isEmpty
            ? 'OpenTelemetry 上传失败：HTTP ${response.statusCode}'
            : 'OpenTelemetry 上传失败：HTTP ${response.statusCode} $body',
      );
    }
  }
}

class OtlpLogRecord {
  final int timeUnixNano;
  final String severityText;
  final String body;
  final Map<String, OtlpValue> attributes;

  const OtlpLogRecord({
    required this.timeUnixNano,
    required this.severityText,
    required this.body,
    this.attributes = const {},
  });
}

sealed class OtlpValue {
  const OtlpValue();
  const factory OtlpValue.string(String value) = OtlpStringValue;
  const factory OtlpValue.int(int value) = OtlpIntValue;
  const factory OtlpValue.bool(bool value) = OtlpBoolValue;
}

class OtlpStringValue extends OtlpValue {
  final String value;
  const OtlpStringValue(this.value);
}

class OtlpIntValue extends OtlpValue {
  final int value;
  const OtlpIntValue(this.value);
}

class OtlpBoolValue extends OtlpValue {
  final bool value;
  const OtlpBoolValue(this.value);
}

class OtlpExportException implements Exception {
  final String message;
  const OtlpExportException(this.message);
  @override
  String toString() => message;
}

Map<String, dynamic> _logRecordJson(OtlpLogRecord record) => {
      'timeUnixNano': record.timeUnixNano.toString(),
      'severityText': record.severityText,
      'body': {'stringValue': record.body},
      'attributes': record.attributes.entries
          .map((e) => _attributeJson(e.key, e.value))
          .toList(),
    };

Map<String, dynamic> _attributeJson(String key, OtlpValue value) => {
      'key': key,
      'value': switch (value) {
        OtlpStringValue(:final value) => {'stringValue': value},
        OtlpIntValue(:final value) => {'intValue': value.toString()},
        OtlpBoolValue(:final value) => {'boolValue': value},
      },
    };
