import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

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
  final String wsUrl;
  final String baseUrl;

  NetworkStatus? currentStatus;
  double? cpuUsage;
  double? memoryUsage;
  Duration pollingInterval = const Duration(seconds: 30);
  WebSocket? _socket;
  StreamSubscription<dynamic>? _socketSubscription;
  Timer? _reconnectTimer;
  Timer? _statusCheckTimer;
  bool _isDisposed = false;

  bool isRunning = false;
  String? errorMessage;

  StatusService({
    this.wsUrl = 'ws://127.0.0.1:8000/ws/statuses',
    this.baseUrl = 'http://127.0.0.1:8000',
  });

  Future<void> startBackend() async {
    await _connect();
    _startStatusCheck();
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
    _startStatusCheck();
    notifyListeners();
  }

  Future<void> _fetchCpuMemoryStatus() async {
    if (_isDisposed) return;
    
    try {
      final cpuResponse = await http.get(
        Uri.parse('$baseUrl/status/cpu'),
      ).timeout(const Duration(seconds: 5));
      
      final memResponse = await http.get(
        Uri.parse('$baseUrl/status/memory'),
      ).timeout(const Duration(seconds: 5));

      if (cpuResponse.statusCode == 200 && memResponse.statusCode == 200) {
        final cpuData = jsonDecode(cpuResponse.body) as Map<String, dynamic>;
        final memData = jsonDecode(memResponse.body) as Map<String, dynamic>;

        cpuUsage = (cpuData['cpu'] as num?)?.toDouble() ?? 0.0;
        memoryUsage = (memData['memory'] as num?)?.toDouble() ?? 0.0;
        errorMessage = null;
        notifyListeners();
      }
    } catch (e) {
      debugPrint('Error fetching CPU/memory status: $e');
    }
  }

  Future<void> _connect() async {
    if (_isDisposed || isRunning) return;

    try {
      _socket = await WebSocket.connect(wsUrl);
      isRunning = true;
      errorMessage = null;
      notifyListeners();

      _socketSubscription = _socket!.listen(
        (data) {
          try {
            final payload = data is String ? data : utf8.decode(data as List<int>);
            final decoded = jsonDecode(payload) as Map<String, dynamic>;

            currentStatus = NetworkStatus.fromJson(decoded);
            notifyListeners();
          } catch (e) {
            debugPrint('Error parsing websocket status payload: $e');
          }
        },
        onDone: _handleSocketClosed,
        onError: (error) {
          errorMessage = 'WebSocket error: $error';
          isRunning = false;
          notifyListeners();
          _scheduleReconnect();
        },
        cancelOnError: true,
      );
    } catch (e) {
      errorMessage = 'Failed to connect to backend websocket: $e';
      isRunning = false;
      notifyListeners();
      _scheduleReconnect();
    }
  }

  void _handleSocketClosed() {
    isRunning = false;
    notifyListeners();
    _scheduleReconnect();
  }

  void _scheduleReconnect() {
    if (_isDisposed) return;
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 3), () {
      _connect();
    });
  }

  void stopBackend() {
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _statusCheckTimer?.cancel();
    _statusCheckTimer = null;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _socket?.close();
    _socket = null;
    isRunning = false;
    currentStatus = null;
    cpuUsage = null;
    memoryUsage = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _isDisposed = true;
    stopBackend();
    super.dispose();
  }
}