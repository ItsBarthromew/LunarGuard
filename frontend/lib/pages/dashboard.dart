import 'package:flutter/material.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:lunarguard/consts/colors.dart';
import 'package:lunarguard/services/status_service.dart';
import 'package:provider/provider.dart';

class Dashboard extends StatefulWidget {
  const Dashboard({super.key});

  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    super.dispose();
  }

  String _formatBytes(int bytes) {
    const suffixes = ['B', 'KB', 'MB', 'GB', 'TB'];
    double value = bytes.toDouble();
    var suffixIndex = 0;

    while (value >= 1024 && suffixIndex < suffixes.length - 1) {
      value /= 1024;
      suffixIndex++;
    }

    final formatted = value >= 10 || value % 1 == 0
        ? value.toStringAsFixed(0)
        : value.toStringAsFixed(1);

    return '$formatted ${suffixes[suffixIndex]}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: backgroundColor,
      body: Center(
        child: Row(
          mainAxisAlignment: MainAxisAlignment.start,
          children: [
            // Sidebar
            Container(
              width: 258.w,
              height: 830.h,
              decoration: BoxDecoration(
                color: mainColor,
                borderRadius: BorderRadius.only(
                  topRight: Radius.circular(40.r),
                  bottomRight: Radius.circular(40.r),
                ),
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.start,
                children: [
                  SizedBox(height: 50.h),
                  // Logo and Title
                  Row(
                    mainAxisAlignment: MainAxisAlignment.start,
                    children: [
                      SizedBox(width: 10.w),
                      Image.asset(
                        'assets/images/logo.png',
                        width: 60.w,
                        height: 60.h,
                      ),
                      Column(
                        mainAxisAlignment: MainAxisAlignment.start,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'LVNΛR GVΛRD',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "Orbitron",
                              color: onMainColor,
                              fontWeight: FontWeight.bold,
                              height: 0.8.h,
                            ),
                          ),
                          Text(
                            'MUFAYA VERSION BETA 1.0',
                            style: TextStyle(
                              fontSize: 10.sp,
                              fontFamily: "ClarendonBold",
                              fontWeight: FontWeight.bold,
                              color: greyColor,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),

                  SizedBox(height: 50.h),
                  // Navigation Items
                  Column(
                    mainAxisAlignment: MainAxisAlignment.start,
                    children: [
                      // Dashboard
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        children: [
                          SizedBox(width: 20.w),
                          Image.asset(
                            'assets/images/dashboard.png',
                            width: 30.w,
                            height: 30.h,
                            color: onMainColor,
                          ),
                          SizedBox(width: 12.w),
                          Text(
                            'DASHBOARD',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "ClarendonBold",
                              color: onMainColor,
                            ),
                          ),
                        ],
                      ),
                      SizedBox(height: 20.h),
                      // Alerts
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        children: [
                          SizedBox(width: 20.w),
                          Image.asset(
                            'assets/images/Notification.png',
                            width: 30.w,
                            height: 30.h,
                            color: greyColor,
                          ),
                          SizedBox(width: 12.w),
                          Text(
                            'ALERTS',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "ClarendonBold",
                              color: greyColor,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),

                      SizedBox(height: 20.h),
                      // Logs
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        children: [
                          SizedBox(width: 20.w),
                          Image.asset(
                            'assets/images/terminal.png',
                            width: 30.w,
                            height: 30.h,
                            color: greyColor,
                          ),
                          SizedBox(width: 12.w),
                          Text(
                            'LOGS',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "ClarendonBold",
                              color: greyColor,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),

                      SizedBox(height: 20.h),
                      //Devices
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        children: [
                          SizedBox(width: 20.w),
                          Image.asset(
                            'assets/images/Devices.png',
                            width: 30.w,
                            height: 30.h,
                            color: greyColor,
                          ),
                          SizedBox(width: 12.w),
                          Text(
                            'DEVICES',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "ClarendonBold",
                              color: greyColor,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),

                      SizedBox(height: 20.h),
                      //Rules
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        children: [
                          SizedBox(width: 20.w),
                          Image.asset(
                            'assets/images/Rules.png',
                            width: 30.w,
                            height: 30.h,
                            color: greyColor,
                          ),
                          SizedBox(width: 12.w),
                          Text(
                            'RULES',
                            style: TextStyle(
                              fontSize: 16.sp,
                              fontFamily: "ClarendonBold",
                              color: greyColor,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ],
              ),
            ),
            SizedBox(width: 10.w),
            Column(
              mainAxisAlignment: MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(height: 10.h),
                // Header with Search and User Info
                Container(
                  width: 940.w,
                  height: 80.h,
                  decoration: BoxDecoration(
                    color: mainColor,
                    borderRadius: BorderRadius.circular(20.r),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Padding(
                        padding: EdgeInsets.symmetric(horizontal: 30.w),
                        child: Container(
                          width: 390.w,
                          height: 44.h,
                          decoration: BoxDecoration(
                            color: backgroundColor,
                            borderRadius: BorderRadius.circular(10.r),
                          ),
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.start,
                            children: [
                              SizedBox(width: 10.w),
                              Image.asset(
                                'assets/images/search.png',
                                width: 30.w,
                                height: 30.h,
                                color: greyColor,
                              ),
                              SizedBox(width: 12.w),
                              Text(
                                'Search Logs, IPs, or Incidents',
                                style: TextStyle(
                                  fontSize: 12.sp,
                                  fontFamily: "ClarendonBold",
                                  color: greyColor,
                                ),
                              ),
                              SizedBox(width: 20.w),
                            ],
                          ),
                        ),
                      ),
                      SizedBox(width: 100.w),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.start,
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          Padding(
                            padding: EdgeInsets.symmetric(vertical: 10.sp),
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.end,
                              crossAxisAlignment: CrossAxisAlignment.end,
                              children: [
                                Text(
                                  'JOHN DOE',
                                  style: TextStyle(
                                    fontSize: 24.sp,
                                    fontFamily: "ClarendonBold",
                                    height: 0.8.h,
                                    color: onMainColor,
                                  ),
                                  textAlign: TextAlign.right,
                                ),
                                Text(
                                  'FULL ACCESS TIER',
                                  style: TextStyle(
                                    fontSize: 10.sp,
                                    fontFamily: "ClarendonBold",
                                    color: onMainColor,
                                  ),
                                  textAlign: TextAlign.right,
                                ),
                                Text(
                                  '05 APRIL 2026, 12:00:00',
                                  textAlign: TextAlign.right,
                                  style: TextStyle(
                                    fontSize: 14.sp,
                                    height: 0.6.h,
                                    fontFamily: "ClarendonBold",
                                    color: onMainColor,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Padding(
                            padding: EdgeInsets.symmetric(vertical: 10.sp),
                            child: Container(
                              width: 50.w,
                              height: 50.h,
                              decoration: BoxDecoration(
                                color: greyColor,
                                shape: BoxShape.circle,
                              ),
                            ),
                          ),
                          SizedBox(height: 4.h),
                        ],
                      ),
                    ],
                  ),
                ),

                SizedBox(height: 10.h),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    //Stats
                    Column(
                      children: [
                        Row(
                          children: [
                            //Active Threats
                            Container(
                              width: 210.w,
                              height: 120.h,
                              decoration: BoxDecoration(
                                color: mainColor,
                                borderRadius: BorderRadius.circular(20.r),
                              ),
                              child: Padding(
                                padding: EdgeInsets.symmetric(
                                  horizontal: 14.w,
                                  vertical: 12.h,
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'ACTIVE THREATS',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        height: 0.6.h,
                                        fontFamily: "ClarendonBold",
                                        color: greyColor,
                                      ),
                                    ),
                                    Text(
                                      '- 100%',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        fontFamily: "ClarendonBold",
                                        color: positiveColor,
                                      ),
                                    ),
                                    Text(
                                      '0',
                                      style: TextStyle(
                                        fontSize: 36.sp,
                                        height: 0.9.h,
                                        fontFamily: "ClarendonBold",
                                        color: onMainColor,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),

                            //Logs Processed
                            SizedBox(width: 10.w),
                            Container(
                              width: 210.w,
                              height: 120.h,
                              decoration: BoxDecoration(
                                color: mainColor,
                                borderRadius: BorderRadius.circular(20.r),
                              ),
                              child: Padding(
                                padding: EdgeInsets.symmetric(
                                  horizontal: 14.w,
                                  vertical: 12.h,
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'LOGS PROCESSED',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        height: 0.6.h,
                                        fontFamily: "ClarendonBold",
                                        color: greyColor,
                                      ),
                                    ),
                                    Text(
                                      '- 10%',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        fontFamily: "ClarendonBold",
                                        color: positiveColor,
                                      ),
                                    ),
                                    Text(
                                      '2.6M',
                                      style: TextStyle(
                                        fontSize: 36.sp,
                                        height: 0.9.h,
                                        fontFamily: "ClarendonBold",
                                        color: onMainColor,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),

                            //Protected Devices
                            SizedBox(width: 10.w),
                            Container(
                              width: 210.w,
                              height: 120.h,
                              decoration: BoxDecoration(
                                color: mainColor,
                                borderRadius: BorderRadius.circular(20.r),
                              ),
                              child: Padding(
                                padding: EdgeInsets.symmetric(
                                  horizontal: 14.w,
                                  vertical: 12.h,
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'PROTECTED DEVICES',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        height: 0.6.h,
                                        fontFamily: "ClarendonBold",
                                        color: greyColor,
                                      ),
                                    ),
                                    Text(
                                      '+ 3%',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        fontFamily: "ClarendonBold",
                                        color: positiveColor2,
                                      ),
                                    ),
                                    Text(
                                      '2',
                                      style: TextStyle(
                                        fontSize: 36.sp,
                                        height: 0.9.h,
                                        fontFamily: "ClarendonBold",
                                        color: onMainColor,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ],
                        ),
                        SizedBox(height: 10.h),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            //Quick Actions
                            Container(
                              width: 322.w,
                              height: 500.h,
                              decoration: BoxDecoration(
                                color: mainColor,
                                borderRadius: BorderRadius.circular(20.r),
                              ),
                              child: Padding(
                                padding: EdgeInsets.symmetric(
                                  horizontal: 14.w,
                                  vertical: 14.h,
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'QUICK ACTIONS',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        height: 0.6.h,
                                        fontFamily: "ClarendonBold",
                                        color: greyColor,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),

                            SizedBox(width: 10.w),

                            //Connected Devices
                            Container(
                              width: 322.w,
                              height: 500.h,
                              decoration: BoxDecoration(
                                color: mainColor,
                                borderRadius: BorderRadius.circular(20.r),
                              ),
                              child: Padding(
                                padding: EdgeInsets.symmetric(
                                  horizontal: 14.w,
                                  vertical: 14.h,
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'CONNECTED DEVICES',
                                      style: TextStyle(
                                        fontSize: 14.sp,
                                        height: 0.6.h,
                                        fontFamily: "ClarendonBold",
                                        color: greyColor,
                                      ),
                                    ),
                                    SizedBox(height: 20.h),

                                    //Computer Device
                                    Center(
                                      child: Column(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Image.asset(
                                            'assets/images/Computers.png',
                                            width: 50.w,
                                            height: 50.h,
                                            color: greyColor,
                                          ),
                                          Text(
                                            'WINDOWS LAPTOP',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.8.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),
                                          Text(
                                            '192.168.1.100',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.9.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),
                                          Text(
                                            'Active',
                                            style: TextStyle(
                                              fontSize: 10.sp,
                                              fontFamily: "ClarendonBold",
                                              color: positiveColor,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),

                                    SizedBox(height: 20.h),
                                    //Mobile Device
                                    Center(
                                      child: Column(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Image.asset(
                                            'assets/images/Phones.png',
                                            width: 50.w,
                                            height: 50.h,
                                            color: greyColor,
                                          ),
                                          Text(
                                            'ANDROID PHONE',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.8.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),
                                          Text(
                                            '192.168.1.100',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.9.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),
                                          Text(
                                            'Active',
                                            style: TextStyle(
                                              fontSize: 10.sp,
                                              fontFamily: "ClarendonBold",
                                              color: positiveColor,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),

                                    SizedBox(height: 20.h),
                                    //Network Device
                                    Center(
                                      child: Column(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Image.asset(
                                            'assets/images/Router.png',
                                            width: 50.w,
                                            height: 50.h,
                                            color: greyColor,
                                          ),
                                          SizedBox(height: 4.h),
                                          Text(
                                            'NETWORK ROUTER',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.8.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),

                                          Text(
                                            '192.168.1.1',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.9.h,
                                              fontFamily: "ClarendonBold",
                                              color: onMainColor,
                                            ),
                                          ),
                                          Text(
                                            'Active',
                                            style: TextStyle(
                                              fontSize: 10.sp,
                                              fontFamily: "ClarendonBold",
                                              color: positiveColor,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),

                                    SizedBox(height: 20.h),
                                    //Offline Device
                                    Center(
                                      child: Column(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Image.asset(
                                            'assets/images/Computers.png',
                                            width: 50.w,
                                            height: 50.h,
                                            color: greyColor,
                                          ),
                                          Text(
                                            'APPLE COMPUTER',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.8.h,
                                              fontFamily: "ClarendonBold",
                                              color: greyColor,
                                            ),
                                          ),
                                          Text(
                                            '192.168.1.100',
                                            style: TextStyle(
                                              fontSize: 14.sp,
                                              height: 0.9.h,
                                              fontFamily: "ClarendonBold",
                                              color: greyColor,
                                            ),
                                          ),
                                          Text(
                                            'Offline',
                                            style: TextStyle(
                                              fontSize: 10.sp,
                                              fontFamily: "ClarendonBold",
                                              color: negativeColor,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),

                    SizedBox(width: 10.w),
                    Column(
                      children: [
                        Container(
                          width: 272.w,
                          height: 360.h,
                          decoration: BoxDecoration(
                            color: mainColor,
                            borderRadius: BorderRadius.circular(20.r),
                          ),
                          child: Padding(
                            padding: EdgeInsets.symmetric(
                              horizontal: 14.w,
                              vertical: 14.h,
                            ),
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.start,
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'WEB SOCKET STATUS',
                                  style: TextStyle(
                                    fontSize: 14.sp,
                                    height: 0.6.h,
                                    fontFamily: "ClarendonBold",
                                    color: greyColor,
                                  ),
                                ),
                                SizedBox(height: 20.h),
                                Expanded(
                                  child: Consumer<StatusService>(
                                    builder: (context, statusService, child) {
                                      final currentStatus =
                                          statusService.currentStatus;

                                      if (currentStatus == null) {
                                        return Align(
                                          alignment: Alignment.topLeft,
                                          child: Text(
                                            'Waiting for websocket stats...',
                                            style: TextStyle(
                                              fontSize: 12.sp,
                                              fontFamily: "Clarendon",
                                              color: greyColor,
                                            ),
                                          ),
                                        );
                                      }

                                      return Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.start,
                                        children: [
                                          Text(
                                            statusService.isRunning
                                                ? 'CONNECTED'
                                                : 'DISCONNECTED',
                                            style: TextStyle(
                                              fontSize: 12.sp,
                                              height: 0.8.h,
                                              fontFamily: "ClarendonBold",
                                              color: statusService.isRunning
                                                  ? positiveColor
                                                  : negativeColor,
                                            ),
                                          ),
                                          SizedBox(height: 18.h),
                                          _statusRow(
                                            label: 'Bytes sent',
                                            value: _formatBytes(
                                              currentStatus.bytesSent,
                                            ),
                                          ),
                                          SizedBox(height: 14.h),
                                          _statusRow(
                                            label: 'Bytes received',
                                            value: _formatBytes(
                                              currentStatus.bytesReceived,
                                            ),
                                          ),
                                          SizedBox(height: 14.h),
                                          _statusRow(
                                            label: 'Last update',
                                            value:
                                                '${currentStatus.updatedAt.hour.toString().padLeft(2, '0')}:${currentStatus.updatedAt.minute.toString().padLeft(2, '0')}:${currentStatus.updatedAt.second.toString().padLeft(2, '0')}',
                                          ),
                                          if (statusService.errorMessage != null)
                                            Padding(
                                              padding:
                                                  EdgeInsets.only(top: 16.h),
                                              child: Text(
                                                statusService.errorMessage!,
                                                style: TextStyle(
                                                  fontSize: 10.sp,
                                                  fontFamily: "Clarendon",
                                                  color: negativeColor,
                                                ),
                                              ),
                                            ),
                                        ],
                                      );
                                    },
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        SizedBox(height: 10.h),
                        Container(
                          height: 260.h,
                          width: 272.w,
                          decoration: BoxDecoration(
                            color: mainColor,
                            borderRadius: BorderRadius.circular(20.r),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
                SizedBox(height: 20.h),

                //System Status
                Container(
                  height: 60.h,
                  width: 940.w,
                  decoration: BoxDecoration(
                    color: mainColor,
                    borderRadius: BorderRadius.circular(20.r),
                  ),
                  child: Consumer<StatusService>(
                    builder: (context, statusService, child) {
                      final cpuValue = statusService.cpuUsage ?? 0.0;
                      final memValue = statusService.memoryUsage ?? 0.0;
                      
                      return Row(
                        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          //Memory Usage
                          Text(
                            'MEM: ${memValue.toStringAsFixed(1)}%',
                            style: TextStyle(
                              fontSize: 12.sp,
                              height: 0.8.h,
                              fontFamily: "ClarendonBold",
                              color: memValue > 80 ? negativeColor : positiveColor,
                            ),
                          ),

                          //CPU Usage
                          Text(
                            'CPU: ${cpuValue.toStringAsFixed(1)}%',
                            style: TextStyle(
                              fontSize: 12.sp,
                              height: 0.8.h,
                              fontFamily: "ClarendonBold",
                              color: cpuValue > 80 ? negativeColor : positiveColor,
                            ),
                          ),

                          //Status (Online/Offline etc.)
                          Text(
                            'STATUS: ${statusService.isRunning ? 'ONLINE' : 'OFFLINE'}',
                            style: TextStyle(
                              fontSize: 12.sp,
                              height: 0.8.h,
                              fontFamily: "ClarendonBold",
                              color: statusService.isRunning ? positiveColor : negativeColor,
                            ),
                          ),

                          //Health (Good/Fair/Poor)
                          Text(
                            'HEALTH: ${_getHealthStatus(cpuValue, memValue)}',
                            style: TextStyle(
                              fontSize: 12.sp,
                              height: 0.8.h,
                              fontFamily: "ClarendonBold",
                              color: _getHealthColor(cpuValue, memValue),
                            ),
                          ),

                          //Latency (ms)
                          Text(
                            'LATENCY: ${(statusService.currentStatus?.updatedAt.millisecondsSinceEpoch ?? 0) % 100}MS',
                            style: TextStyle(
                              fontSize: 12.sp,
                              height: 0.8.h,
                              fontFamily: "ClarendonBold",
                              color: positiveColor,
                            ),
                          ),
                        ],
                      );
                    },
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _statusRow({required String label, required String value}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: TextStyle(
            fontSize: 12.sp,
            fontFamily: "ClarendonBold",
            color: greyColor,
          ),
        ),
        Flexible(
          child: Text(
            value,
            textAlign: TextAlign.right,
            style: TextStyle(
              fontSize: 12.sp,
              fontFamily: "ClarendonBold",
              color: onMainColor,
            ),
          ),
        ),
      ],
    );
  }

  String _getHealthStatus(double cpu, double memory) {
    final avgUsage = (cpu + memory) / 2;
    if (avgUsage < 50) return 'GOOD';
    if (avgUsage < 75) return 'FAIR';
    return 'POOR';
  }

  Color _getHealthColor(double cpu, double memory) {
    final avgUsage = (cpu + memory) / 2;
    if (avgUsage < 50) return positiveColor;
    if (avgUsage < 75) return greyColor;
    return negativeColor;
  }
}
