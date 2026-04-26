import 'package:flutter/material.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:provider/provider.dart';
import 'package:lunarguard/pages/dashboard.dart';
import 'package:lunarguard/services/status_service.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ScreenUtilInit(
      designSize: const Size(1280, 830),
      child: ChangeNotifierProvider(
        create: (_) => StatusService()..startBackend(),
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          title: 'LVNΛR GUΛRD',
          home: const Dashboard(),
        ),
      ),
    );
  }
}