import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

class LiveLogEntry {
  final String time;
  final String tag;
  final String message;

  const LiveLogEntry({
    required this.time,
    required this.tag,
    required this.message,
  });
}

class NetworkStatus {
  final int bytesSent;
  final int bytesReceived;
  final DateTime updatedAt;

  NetworkStatus({
    required this.bytesSent,
    required this.bytesReceived,
    required this.updatedAt,
  });

  factory NetworkStatus.fromJson(Map<String, dynamic> json) {
    return NetworkStatus(
      bytesSent: (json['bytes_sent'] as num?)?.toInt() ?? 0,
      bytesReceived: (json['bytes_recv'] as num?)?.toInt() ?? 0,
      updatedAt: DateTime.now(),
    );
  }
}

class StatusService extends ChangeNotifier {
  final String baseUrl;
  final String logsWsUrl;

  NetworkStatus? currentStatus;
  double? cpuUsage;
  double? memoryUsage;
  double? healthCpuAverage;
  double? healthMemoryAverage;
  String? memoryRouteResult;
  int? latencyMs;
  String? healthStatus;
  double? diskUsage;
  Map<String, dynamic>? networkUsage;
  final List<String> routeOutputs = [];
  final List<LiveLogEntry> liveLogs = [];
  Duration pollingInterval = const Duration(seconds: 30);
  DateTime? lastSuccessfulDataAt;
  double _cpuBatchSum = 0;
  double _memoryBatchSum = 0;
  int _healthBatchCount = 0;
  Timer? _statusCheckTimer;
  Timer? _logReconnectTimer;
  StreamSubscription<dynamic>? _logsSubscription;
  WebSocketChannel? _logsSocket;
  bool _isDisposed = false;
  bool _isFetchingStatus = false;
  bool _isFetchingRouteOutputs = false;
  bool _isConnectingLogs = false;
  bool _hasAnnouncedLogConnection = false;

  bool isRunning = false;
  String? errorMessage;

  bool get isOnline {
    if (isRunning) return true;
    if (lastSuccessfulDataAt == null) return false;
    return DateTime.now().difference(lastSuccessfulDataAt!) <= pollingInterval + const Duration(seconds: 10);
  }

  int get _healthSampleTarget {
    final seconds = pollingInterval.inSeconds;
    if (seconds <= 1) return 20;
    if (seconds <= 5) return 10;
    return 5;
  }

  StatusService({String? baseUrl})
      : baseUrl = _resolveBackendUrl(baseUrl ?? dotenv.env['BACKEND_URL'] ?? 'http://localhost:8000'),
        logsWsUrl = _toLogsWsUrl(_resolveBackendUrl(baseUrl ?? dotenv.env['BACKEND_URL'] ?? 'http://localhost:8000'));

  static String _toLogsWsUrl(String baseUrl) {
    final uri = Uri.parse(baseUrl);
    final scheme = uri.scheme == 'https' ? 'wss' : 'ws';
    return '$scheme://${uri.host}:${uri.port}/ws/logs';
  }

  static String _resolveBackendUrl(String backendUrl) {
    final uri = Uri.parse(backendUrl);

    if (!kIsWeb &&
        defaultTargetPlatform == TargetPlatform.android &&
        (uri.host == 'localhost' || uri.host == '127.0.0.1')) {
      return uri.replace(host: '10.0.2.2').toString();
    }

    return backendUrl;
  }

  Future<void> startBackend() async {
    debugPrint('StatusService starting: baseUrl=$baseUrl');
    _connectLogsStream();
    _startStatusCheck();
    _fetchRouteOutputs();
  }

  void _addSystemLiveLog(String tag, String message) {
    _addLiveLog(
      LiveLogEntry(
        time: DateTime.now().toIso8601String().substring(11, 19),
        tag: tag,
        message: message,
      ),
    );
  }

  Future<String> _resolveLogsWsUrl() async {
    final fallback = logsWsUrl;

    try {
      final response = await http
          .get(Uri.parse('$baseUrl/logs/ws-info'))
          .timeout(const Duration(seconds: 5));

      if (response.statusCode != 200) return fallback;

      final decoded = jsonDecode(response.body);
      if (decoded is! Map<String, dynamic>) return fallback;

      final dynamic urlValue = decoded['websocket_url'];
      if (urlValue is String && urlValue.isNotEmpty) {
        return urlValue;
      }
    } catch (_) {
      // Fall back to derived URL.
    }

    return fallback;
  }

  void _addLiveLog(LiveLogEntry entry) {
    liveLogs.add(entry);
    if (liveLogs.length > 500) {
      liveLogs.removeRange(0, liveLogs.length - 500);
    }
    notifyListeners();
  }

  void _connectLogsStream() {
    if (_isDisposed || _isConnectingLogs) return;
    _isConnectingLogs = true;

    () async {
      try {
        final wsUrl = await _resolveLogsWsUrl();
        _logsSocket = WebSocketChannel.connect(Uri.parse(wsUrl));

        try {
          await _logsSocket!.ready;
        } catch (e) {
          _addSystemLiveLog('[WARN]', 'Live log handshake failed: $e');
          _scheduleLogReconnect();
          return;
        }

        if (!_hasAnnouncedLogConnection) {
          _hasAnnouncedLogConnection = true;
          _addSystemLiveLog('[INFO]', 'Connected to live logs stream ($wsUrl)');
        }

        _logsSubscription = _logsSocket!.stream.listen(
          (dynamic data) {
            try {
              final payload = data is String ? data : utf8.decode(data as List<int>);
              final parsed = jsonDecode(payload);
              if (parsed is! Map<String, dynamic>) return;

              final time = (parsed['time'] ?? '--:--:--').toString();
              final tag = (parsed['tag'] ?? '[INFO]').toString();
              final message = (parsed['msg'] ?? '').toString();

              _addLiveLog(LiveLogEntry(time: time, tag: tag, message: message));
            } catch (e) {
              _addSystemLiveLog('[ERROR]', 'Failed to parse live log payload: $e');
            }
          },
          onDone: _scheduleLogReconnect,
          onError: (error) {
            _addSystemLiveLog('[WARN]', 'Live log connection error: $error');
            _scheduleLogReconnect();
          },
          cancelOnError: true,
        );
      } catch (e) {
        _addSystemLiveLog('[WARN]', 'Unable to connect to live logs stream: $e');
        _scheduleLogReconnect();
      } finally {
        _isConnectingLogs = false;
      }
    }();
  }

  void _scheduleLogReconnect() {
    if (_isDisposed) return;
    _logReconnectTimer?.cancel();
    _addSystemLiveLog('[WARN]', 'Reconnecting to live logs stream...');
    _logReconnectTimer = Timer(const Duration(seconds: 2), _connectLogsStream);
  }

  Future<void> _startStatusCheck() async {
    if (_isDisposed) return;
    _statusCheckTimer?.cancel();
    
    // Fetch immediately
    await _fetchCpuMemoryStatus();
    
    // Then poll at the configured interval
    _statusCheckTimer = Timer.periodic(pollingInterval, (_) {
      _fetchCpuMemoryStatus();
    });
  }

  void setPollingInterval(Duration interval) {
    if (_isDisposed) return;
    pollingInterval = interval;
    _resetHealthBatch();
    _startStatusCheck();
    notifyListeners();
  }

  void _resetHealthBatch() {
    _cpuBatchSum = 0;
    _memoryBatchSum = 0;
    _healthBatchCount = 0;
  }

  void _updateHealthAverages(double cpu, double memory) {
    if (healthCpuAverage == null || healthMemoryAverage == null) {
      healthCpuAverage = cpu;
      healthMemoryAverage = memory;
      _cpuBatchSum = cpu;
      _memoryBatchSum = memory;
      _healthBatchCount = 1;
      return;
    }

    if (_healthBatchCount == 0) {
      // Start the next batch from the previous displayed result.
      _cpuBatchSum = healthCpuAverage!;
      _memoryBatchSum = healthMemoryAverage!;
      _healthBatchCount = 1;
    }

    _cpuBatchSum += cpu;
    _memoryBatchSum += memory;
    _healthBatchCount += 1;

    if (_healthBatchCount >= _healthSampleTarget) {
      healthCpuAverage = _cpuBatchSum / _healthBatchCount;
      healthMemoryAverage = _memoryBatchSum / _healthBatchCount;
      _resetHealthBatch();
    }
  }

  Future<void> _fetchCpuMemoryStatus() async {
    if (_isDisposed || _isFetchingStatus) return;
    _isFetchingStatus = true;
    
    try {
      debugPrint('Fetching MEM route: $baseUrl/status/memory');
      final t0 = DateTime.now().millisecondsSinceEpoch;
      final cpuResponse = await http.get(
        Uri.parse('$baseUrl/status/cpu'),
      ).timeout(const Duration(seconds: 10));
      
      final memResponse = await http.get(
        Uri.parse('$baseUrl/status/memory?t0=$t0'),
      ).timeout(const Duration(seconds: 10));
      final t2 = DateTime.now().millisecondsSinceEpoch;

      debugPrint('CPU route status=${cpuResponse.statusCode} body=${cpuResponse.body}');
      debugPrint('MEM route status=${memResponse.statusCode} body=${memResponse.body}');

      if (cpuResponse.statusCode == 200 && memResponse.statusCode == 200) {
        final cpuData = jsonDecode(cpuResponse.body) as Map<String, dynamic>;
        final memData = jsonDecode(memResponse.body) as Map<String, dynamic>;

        isRunning = true;
        cpuUsage = (cpuData['cpu'] as num?)?.toDouble() ?? 0.0;
        memoryUsage = (memData['memory'] as num?)?.toDouble() ?? 0.0;
        _updateHealthAverages(cpuUsage!, memoryUsage!);
        memoryRouteResult = memResponse.body;
        latencyMs = t2 - t0;
        lastSuccessfulDataAt = DateTime.now();
        errorMessage = null;
        notifyListeners();
      } else {
        isRunning = false;
        errorMessage = 'Status endpoints returned non-200 responses.';
        debugPrint('MEM fetch returned non-200 response');
        notifyListeners();
      }
    } catch (e) {
      isRunning = false;
      errorMessage = 'Failed to fetch status: $e';
      notifyListeners();
      debugPrint('Error fetching CPU/memory status: $e');
    } finally {
      _isFetchingStatus = false;
    }
  }

  Future<void> _fetchRouteOutputs() async {
    if (_isDisposed || _isFetchingRouteOutputs) return;
    _isFetchingRouteOutputs = true;

    try {
      debugPrint('Fetching API route outputs from $baseUrl');
      final responses = await Future.wait([
        http.get(Uri.parse('$baseUrl/health')).timeout(const Duration(seconds: 10)),
        http.get(Uri.parse('$baseUrl/status/cpu')).timeout(const Duration(seconds: 10)),
        http.get(Uri.parse('$baseUrl/status/memory?t0=${DateTime.now().millisecondsSinceEpoch}')).timeout(const Duration(seconds: 10)),
        http.get(Uri.parse('$baseUrl/status/disk')).timeout(const Duration(seconds: 10)),
        http.get(Uri.parse('$baseUrl/status/network')).timeout(const Duration(seconds: 10)),
      ]);

      routeOutputs
        ..clear()
        ..add('GET /health -> ${responses[0].body}')
        ..add('GET /status/cpu -> ${responses[1].body}')
        ..add('GET /status/memory -> ${responses[2].body}')
        ..add('GET /status/disk -> ${responses[3].body}')
        ..add('GET /status/network -> ${responses[4].body}');

      if (responses[0].statusCode == 200) {
        final body = jsonDecode(responses[0].body);
        healthStatus = body is Map<String, dynamic> ? (body['status'] as String?) : responses[0].body;
      }

      if (responses[3].statusCode == 200) {
        final body = jsonDecode(responses[3].body);
        diskUsage = (body is Map<String, dynamic> ? body['disk'] : null as dynamic) is num
            ? (body['disk'] as num).toDouble()
            : diskUsage;
      }

      if (responses[4].statusCode == 200) {
        final body = jsonDecode(responses[4].body);
        networkUsage = body is Map<String, dynamic> ? body : null;
      }

      lastSuccessfulDataAt = DateTime.now();

      notifyListeners();
    } catch (e) {
      debugPrint('Error fetching API route outputs: $e');
      routeOutputs
        ..clear()
        ..add('Failed to fetch route outputs: $e');
      notifyListeners();
    } finally {
      _isFetchingRouteOutputs = false;
    }
  }

  void stopBackend() {
    _statusCheckTimer?.cancel();
    _statusCheckTimer = null;
    _logReconnectTimer?.cancel();
    _logReconnectTimer = null;
    _logsSubscription?.cancel();
    _logsSubscription = null;
    _logsSocket?.sink.close();
    _logsSocket = null;
    isRunning = false;
    currentStatus = null;
    cpuUsage = null;
    memoryUsage = null;
    healthCpuAverage = null;
    healthMemoryAverage = null;
    memoryRouteResult = null;
    latencyMs = null;
    lastSuccessfulDataAt = null;
    healthStatus = null;
    diskUsage = null;
    networkUsage = null;
    routeOutputs.clear();
    liveLogs.clear();
    _resetHealthBatch();
    notifyListeners();
  }

  @override
  void dispose() {
    _isDisposed = true;
    stopBackend();
    super.dispose();
  }
}